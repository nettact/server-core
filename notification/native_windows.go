//go:build windows

package notification

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// NativeSupported reports whether this build can pop OS desktop notifications.
func NativeSupported() bool { return true }

// appUserModelID is NetTact's own AppUserModelID. The toast is shown under it
// so the notification is attributed to "NetTact" instead of whatever process
// happens to raise it.
const appUserModelID = "NetTact.ServerLite"

// This file talks to the WinRT toast API (Windows.UI.Notifications) directly
// through combase.dll + COM vtable calls. It deliberately spawns NO child
// process: the previous implementation shelled out to
// `powershell.exe -EncodedCommand <base64>`, which is a textbook malware
// signature (MITRE T1059.001) and gets NetTact flagged or blocked by AV/EDR.
// Everything here is in-process syscalls, so there is nothing for a heuristic
// scanner to latch onto.
//
// Incident text is untrusted (target names etc. flow into the summary), so it
// never touches any shell or interpreter — it is XML-escaped and embedded in the
// toast document, which is then handed to XmlDocument.LoadXml as a single
// HSTRING.
//
// When url is non-empty it becomes the toast's launch string with
// activationType="protocol", so clicking the toast opens the incident page in
// the default browser. Protocol activation is the one activation type that
// works for an unpackaged app without a registered COM activator.

// WinRT class names and interface IDs used below.
const (
	classXMLDocument              = "Windows.Data.Xml.Dom.XmlDocument"
	classToastNotification        = "Windows.UI.Notifications.ToastNotification"
	classToastNotificationManager = "Windows.UI.Notifications.ToastNotificationManager"
)

var (
	// {F7F3A506-1E87-42D6-BCFB-B8C809FA5494} Windows.Data.Xml.Dom.IXmlDocument
	iidXMLDocument = windows.GUID{Data1: 0xf7f3a506, Data2: 0x1e87, Data3: 0x42d6,
		Data4: [8]byte{0xbc, 0xfb, 0xb8, 0xc8, 0x09, 0xfa, 0x54, 0x94}}
	// {6CD0E74E-EE65-4489-9EBF-CA43E87BA637} Windows.Data.Xml.Dom.IXmlDocumentIO
	iidXMLDocumentIO = windows.GUID{Data1: 0x6cd0e74e, Data2: 0xee65, Data3: 0x4489,
		Data4: [8]byte{0x9e, 0xbf, 0xca, 0x43, 0xe8, 0x7b, 0xa6, 0x37}}
	// {04124B20-82C6-4229-B109-FD9ED4662B53} IToastNotificationFactory
	iidToastNotificationFactory = windows.GUID{Data1: 0x04124b20, Data2: 0x82c6, Data3: 0x4229,
		Data4: [8]byte{0xb1, 0x09, 0xfd, 0x9e, 0xd4, 0x66, 0x2b, 0x53}}
	// {50AC103F-D235-4598-BBEF-98FE4D1A3AD4} IToastNotificationManagerStatics
	iidToastNotificationManagerStatics = windows.GUID{Data1: 0x50ac103f, Data2: 0xd235, Data3: 0x4598,
		Data4: [8]byte{0xbb, 0xef, 0x98, 0xfe, 0x4d, 0x1a, 0x3a, 0xd4}}
)

// COM vtable slots. 0-2 are IUnknown, 3-5 are IInspectable, so every WinRT
// interface's own methods start at slot 6 in declaration order.
const (
	slotQueryInterface = 0
	slotRelease        = 2

	slotLoadXml                   = 6 // IXmlDocumentIO.LoadXml(HSTRING)
	slotCreateToastNotification   = 6 // IToastNotificationFactory.CreateToastNotification(IXmlDocument*, **IToastNotification)
	slotCreateToastNotifierWithID = 7 // IToastNotificationManagerStatics.CreateToastNotifierWithId(HSTRING, **IToastNotifier)
	slotShow                      = 6 // IToastNotifier.Show(IToastNotification*)
)

const (
	roInitMultithreaded = 1          // RO_INIT_MULTITHREADED
	sFalse              = 0x00000001 // already initialized on this thread
	rpcEChangedMode     = 0x80010106 // thread already in a different apartment
)

var (
	combase                    = windows.NewLazySystemDLL("combase.dll")
	procRoInitialize           = combase.NewProc("RoInitialize")
	procRoUninitialize         = combase.NewProc("RoUninitialize")
	procRoActivateInstance     = combase.NewProc("RoActivateInstance")
	procRoGetActivationFactory = combase.NewProc("RoGetActivationFactory")
	procWindowsCreateString    = combase.NewProc("WindowsCreateString")
	procWindowsDeleteString    = combase.NewProc("WindowsDeleteString")

	winrtOnce sync.Once
	winrtErr  error
)

// loadWinRT resolves the combase entry points once. LazyProc.Call panics when a
// symbol is missing, so every proc is resolved up front and the failure is
// turned into a plain error instead (WinRT needs Windows 8+).
func loadWinRT() error {
	winrtOnce.Do(func() {
		for _, p := range []*windows.LazyProc{
			procRoInitialize, procRoUninitialize, procRoActivateInstance,
			procRoGetActivationFactory, procWindowsCreateString, procWindowsDeleteString,
		} {
			if err := p.Find(); err != nil {
				winrtErr = fmt.Errorf("winrt unavailable: %w", err)
				return
			}
		}
	})
	return winrtErr
}

// toastJob is one queued toast delivery. done is buffered (cap 1) so the worker
// can always hand back a result without blocking, even when the requester has
// already timed out and stopped listening.
type toastJob struct {
	xml  string
	done chan error
}

// toastCh feeds the single toast worker. It is buffered so a short burst of
// notifications queues instead of blocking, but bounded so a wedged WinRT call
// can never grow the backlog — or the goroutine/thread count — without limit.
var (
	toastCh      = make(chan toastJob, 8)
	toastStarted sync.Once
)

// startToastWorker launches the one goroutine that ever touches WinRT. It owns a
// single OS thread for the process lifetime (deliberately never unlocked),
// giving toast delivery a stable COM apartment and guaranteeing that — no matter
// how many notifications fire or how badly WinRT hangs — at most ONE goroutine
// and ONE OS thread are ever dedicated to it. This is what bounds the path the
// previous spawn-per-call design could not: a hung Show() stalls the queue but
// leaks nothing.
func startToastWorker() {
	go func() {
		runtime.LockOSThread()
		for job := range toastCh {
			job.done <- showToast(job.xml)
		}
	}()
}

// nativeNotify shows a Windows toast attributed to NetTact.
//
// The actual COM work runs on the shared toast worker's locked OS thread (WinRT
// apartment state is per-thread and must not leak into the caller's goroutine).
// Both the enqueue and the result wait are raced against ctx, so a wedged WinRT
// call can never block the incident pipeline: once the bounded queue fills, new
// calls fail out on ctx instead of spawning more workers.
func nativeNotify(ctx context.Context, title, body, url string) error {
	if err := loadWinRT(); err != nil {
		return err
	}
	// Registering the AppUserModelID under HKCU\Software\Classes\AppUserModelId
	// (idempotent, current-user only, no admin) is the documented way for an
	// unpackaged app to give its toasts a proper source label. A failure here
	// only costs the label, so the toast still goes out.
	if err := registerAppUserModelID(); err != nil {
		log.Printf("notify system: register AppUserModelID: %v", err)
	}

	toastStarted.Do(startToastWorker)
	job := toastJob{xml: buildToastXML(title, body, url), done: make(chan error, 1)}
	select {
	case toastCh <- job:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-job.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// registerAppUserModelID gives the AppUserModelID a DisplayName so toasts are
// labelled "NetTact" in the notification center.
func registerAppUserModelID() error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Classes\AppUserModelId\`+appUserModelID, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("DisplayName", "NetTact")
}

// buildToastXML renders the ToastGeneric document. title/body/url are untrusted
// and are XML-escaped; xml.EscapeText also replaces characters that are illegal
// in XML (control bytes, NUL) with U+FFFD, so the result always parses.
func buildToastXML(title, body, url string) string {
	var b strings.Builder
	b.WriteString(`<toast`)
	if url != "" {
		b.WriteString(` activationType="protocol" launch="`)
		b.WriteString(escapeXML(url))
		b.WriteString(`"`)
	}
	b.WriteString(`><visual><binding template="ToastGeneric"><text>`)
	b.WriteString(escapeXML(title))
	b.WriteString(`</text><text>`)
	b.WriteString(escapeXML(body))
	b.WriteString(`</text></binding></visual></toast>`)
	return b.String()
}

func escapeXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// showToast runs the WinRT call chain. It must be called on a locked OS thread.
func showToast(toastXML string) error {
	hr, _, _ := procRoInitialize.Call(roInitMultithreaded)
	switch uint32(hr) {
	case 0, sFalse:
		defer procRoUninitialize.Call()
	case rpcEChangedMode:
		// Thread already lives in another apartment; usable as-is, and we must
		// not tear down an apartment we did not create.
	default:
		return hresultError("RoInitialize", hr)
	}

	// XmlDocument.LoadXml(toastXML)
	docInspectable, err := activateInstance(classXMLDocument)
	if err != nil {
		return err
	}
	defer comRelease(docInspectable)

	docIO, err := comQueryInterface(docInspectable, &iidXMLDocumentIO)
	if err != nil {
		return err
	}
	defer comRelease(docIO)

	xmlStr, err := newHString(toastXML)
	if err != nil {
		return err
	}
	defer deleteHString(xmlStr)
	if hr := comCall(docIO, slotLoadXml, uintptr(xmlStr)); failed(hr) {
		return hresultError("IXmlDocumentIO.LoadXml", hr)
	}

	xmlDoc, err := comQueryInterface(docInspectable, &iidXMLDocument)
	if err != nil {
		return err
	}
	defer comRelease(xmlDoc)

	// ToastNotification(xmlDoc)
	toastFactory, err := activationFactory(classToastNotification, &iidToastNotificationFactory)
	if err != nil {
		return err
	}
	defer comRelease(toastFactory)

	var toast unsafe.Pointer
	hr = comCall(toastFactory, slotCreateToastNotification,
		uintptr(xmlDoc), uintptr(unsafe.Pointer(&toast)))
	if failed(hr) {
		return hresultError("IToastNotificationFactory.CreateToastNotification", hr)
	}
	defer comRelease(toast)

	// ToastNotificationManager.CreateToastNotifier(appUserModelID).Show(toast)
	mgr, err := activationFactory(classToastNotificationManager, &iidToastNotificationManagerStatics)
	if err != nil {
		return err
	}
	defer comRelease(mgr)

	appID, err := newHString(appUserModelID)
	if err != nil {
		return err
	}
	defer deleteHString(appID)

	var notifier unsafe.Pointer
	hr = comCall(mgr, slotCreateToastNotifierWithID,
		uintptr(appID), uintptr(unsafe.Pointer(&notifier)))
	if failed(hr) {
		return hresultError("IToastNotificationManagerStatics.CreateToastNotifierWithId", hr)
	}
	defer comRelease(notifier)

	if hr := comCall(notifier, slotShow, uintptr(toast)); failed(hr) {
		return hresultError("IToastNotifier.Show", hr)
	}
	return nil
}

// activateInstance is RoActivateInstance: it constructs a WinRT object by class
// name and returns its IInspectable (caller releases).
func activateInstance(class string) (unsafe.Pointer, error) {
	h, err := newHString(class)
	if err != nil {
		return nil, err
	}
	defer deleteHString(h)
	var inst unsafe.Pointer
	hr, _, _ := procRoActivateInstance.Call(uintptr(h), uintptr(unsafe.Pointer(&inst)))
	if failed(hr) {
		return nil, hresultError("RoActivateInstance("+class+")", hr)
	}
	return inst, nil
}

// activationFactory is RoGetActivationFactory: it returns the static/factory
// interface iid for a WinRT class (caller releases).
func activationFactory(class string, iid *windows.GUID) (unsafe.Pointer, error) {
	h, err := newHString(class)
	if err != nil {
		return nil, err
	}
	defer deleteHString(h)
	var factory unsafe.Pointer
	hr, _, _ := procRoGetActivationFactory.Call(uintptr(h),
		uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&factory)))
	runtime.KeepAlive(iid)
	if failed(hr) {
		return nil, hresultError("RoGetActivationFactory("+class+")", hr)
	}
	return factory, nil
}

// comCall invokes vtable slot idx on a COM interface pointer, passing `this` as
// the implicit first argument.
func comCall(this unsafe.Pointer, idx int, args ...uintptr) uintptr {
	vtbl := *(**[32]uintptr)(this)
	all := make([]uintptr, 0, len(args)+1)
	all = append(all, uintptr(this))
	all = append(all, args...)
	hr, _, _ := syscall.SyscallN(vtbl[idx], all...)
	return hr
}

func comQueryInterface(this unsafe.Pointer, iid *windows.GUID) (unsafe.Pointer, error) {
	var out unsafe.Pointer
	hr := comCall(this, slotQueryInterface,
		uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(iid)
	if failed(hr) {
		return nil, hresultError("QueryInterface", hr)
	}
	return out, nil
}

func comRelease(this unsafe.Pointer) {
	if this != nil {
		comCall(this, slotRelease)
	}
}

// hstring is a WinRT HSTRING handle.
type hstring uintptr

// newHString copies s into a WinRT string. WindowsCreateString takes the length
// in UTF-16 code units, excluding the terminator.
func newHString(s string) (hstring, error) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return 0, fmt.Errorf("winrt string: %w", err)
	}
	var h hstring
	hr, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(u)
	if failed(hr) {
		return 0, hresultError("WindowsCreateString", hr)
	}
	return h, nil
}

func deleteHString(h hstring) {
	if h != 0 {
		procWindowsDeleteString.Call(uintptr(h))
	}
}

// failed reports whether an HRESULT indicates failure (sign bit set).
func failed(hr uintptr) bool { return int32(uint32(hr)) < 0 }

func hresultError(op string, hr uintptr) error {
	return fmt.Errorf("%s: HRESULT 0x%08X", op, uint32(hr))
}
