package fault

import "fmt"

// SignalTitle renders the standard user-facing statement for a fault signal.
//
// The wording is deliberately literal about what was actually observed: a failed
// ICMP probe is reported as "the ICMP probe is unreachable", never as "the device
// is offline". A device that filters ICMP by policy is not down, and claiming so
// from one probe would be the product asserting something it cannot know. Only
// the Agent-connectivity detector, which has direct evidence of the session, is
// allowed to say a thing is offline.
//
// Chinese is the product's default language; the console re-renders from the
// signal's structured fields when it needs English, so this string is a
// server-side default for the timeline and the incident title rather than the
// only representation.
func SignalTitle(s Signal) string { return SignalTitleLang(s, "zh") }

// SignalTitleLang renders the statement in a specific language. Chinese is the
// product default and what the stored incident title and timeline use; English is
// needed by the API, which returns both languages so the console never has to
// re-derive a sentence from raw metric fields.
func SignalTitleLang(s Signal, lang string) string {
	en := lang == "en"
	name := s.TargetName
	if name == "" {
		name = s.TargetAddr
	}
	switch s.DetectorKey {
	case DetectorAgentConnectivity:
		agent := s.AgentName
		if agent == "" {
			agent = s.AgentID
		}
		if en {
			return fmt.Sprintf("Agent %q is offline", agent)
		}
		return fmt.Sprintf("Agent「%s」已离线", agent)
	// The degradation wording is careful in the opposite direction from the fault
	// wording above: where a fault must not overclaim ("unreachable", not
	// "offline"), a degradation must not UNDERclaim its own uncertainty. It says
	// "higher than usual" — a comparison against this target's own history, which
	// is exactly what was measured — rather than "the network is congested", which
	// would be a cause the product did not observe.
	case DetectorLatencyDegradation:
		if en {
			return fmt.Sprintf("%q is markedly slower than usual", name)
		}
		return fmt.Sprintf("「%s」延迟明显高于平时", name)
	case DetectorLossDegradation:
		if en {
			return fmt.Sprintf("%q is losing more packets than usual", name)
		}
		return fmt.Sprintf("「%s」丢包明显高于平时", name)
	}
	// The system-status wording names the resource and the machine, and stops
	// there. "CPU usage is persistently high" is what was measured; "the machine is
	// overloaded" would be a conclusion about whether that matters, which depends
	// on what the machine is for and is exactly the judgement the operator makes by
	// choosing the threshold.
	if family, subject := SplitHostDetectorKey(s.DetectorKey); IsHostDetector(s.DetectorKey) {
		return hostSignalTitle(family, subject, s.TargetName, s.AgentName, en)
	}
	if en {
		return signalTitleEn(s, name)
	}
	switch s.ProbeKind {
	case "gateway":
		if name != "" {
			return fmt.Sprintf("网关「%s」ICMP 探测不可达", name)
		}
		return "网关 ICMP 探测不可达"
	case "icmp":
		return fmt.Sprintf("「%s」的 ICMP 探测不可达", name)
	case "tcp":
		addr := s.TargetAddr
		if s.TargetPortSuffix() != "" {
			addr += s.TargetPortSuffix()
		}
		return fmt.Sprintf("无法连接 %s", addr)
	case "http":
		return fmt.Sprintf("「%s」HTTP 探测失败", name)
	case "dns":
		return fmt.Sprintf("「%s」解析失败", name)
	case "nat":
		return fmt.Sprintf("无法访问 STUN 服务 %s", name)
	}
	if name == "" {
		return "探测失败"
	}
	return fmt.Sprintf("「%s」探测失败", name)
}

// signalTitleEn is the English half of SignalTitleLang. It keeps the same
// literalness: an unanswered ICMP probe is an unreachable probe, not a device
// that is down.
func signalTitleEn(s Signal, name string) string {
	switch s.ProbeKind {
	case "gateway":
		if name != "" {
			return fmt.Sprintf("Gateway %q is not answering ICMP", name)
		}
		return "The gateway is not answering ICMP"
	case "icmp":
		return fmt.Sprintf("%q is not answering ICMP", name)
	case "tcp":
		return fmt.Sprintf("Cannot connect to %s", s.TargetAddr+s.TargetPortSuffix())
	case "http":
		return fmt.Sprintf("The HTTP check for %q failed", name)
	case "dns":
		return fmt.Sprintf("%q failed to resolve", name)
	case "nat":
		return fmt.Sprintf("Cannot reach the STUN service %s", name)
	}
	if name == "" {
		return "The probe failed"
	}
	return fmt.Sprintf("The probe for %q failed", name)
}

// DegradationGroupTitle names a merged degradation incident. A merged
// availability incident is titled with the bare group name, which would be
// indistinguishable here: an operator looking at "客厅设备" twice in the incident
// list, one meaning unreachable and one meaning slow, learns nothing from either.
func DegradationGroupTitle(groupName, lang string) string {
	if lang == "en" {
		return fmt.Sprintf("Network quality in %q has degraded", groupName)
	}
	return fmt.Sprintf("「%s」网络质量下降", groupName)
}

// hostSignalTitle renders a system-status statement. The subject is what makes
// several of these legible — one of four disks being full is a different sentence
// from "a disk is full" — so it is in the title rather than only in the evidence.
//
// The machine is named by the anchor when it has a name and by the Agent
// otherwise, because a host anchor is very often left unnamed: it is created to
// watch every machine in a group, and there is nothing sensible for one name to
// say about all of them. The Agent's name is then the honest answer to "whose
// CPU", and it is the one the reader is looking for anyway.
func hostSignalTitle(family, subject, targetName, agentName string, en bool) string {
	who := targetName
	if who == "" {
		who = agentName
	}
	// The named/unnamed pair is written out for each family rather than assembled
	// from fragments: Chinese and English put the possessor in different places,
	// and a machine with no name at all must still produce a whole sentence.
	named := func(zh, zhAnon, enS, enAnon string) string {
		if en {
			if who == "" {
				return enAnon
			}
			return fmt.Sprintf(enS, who)
		}
		if who == "" {
			return zhAnon
		}
		return fmt.Sprintf(zh, who)
	}
	switch family {
	case DetectorHostCPU:
		return named("「%s」CPU 使用率持续过高", "CPU 使用率持续过高",
			"CPU usage on %q is persistently high", "CPU usage is persistently high")
	case DetectorHostMem:
		return named("「%s」内存使用率持续过高", "内存使用率持续过高",
			"Memory usage on %q is persistently high", "Memory usage is persistently high")
	case DetectorHostLoad:
		return named("「%s」系统负载持续过高", "系统负载持续过高",
			"System load on %q is persistently high", "System load is persistently high")
	case DetectorHostNet:
		if subject == "tx" {
			return named("「%s」上传速率持续超过阈值", "上传速率持续超过阈值",
				"Upload rate on %q is persistently above the threshold",
				"The upload rate is persistently above the threshold")
		}
		return named("「%s」下载速率持续超过阈值", "下载速率持续超过阈值",
			"Download rate on %q is persistently above the threshold",
			"The download rate is persistently above the threshold")
	case DetectorHostDisk:
		if en {
			if who == "" {
				return fmt.Sprintf("Disk %s is almost full", subject)
			}
			return fmt.Sprintf("Disk %s on %q is almost full", subject, who)
		}
		if who == "" {
			return fmt.Sprintf("磁盘 %s 空间不足", subject)
		}
		return fmt.Sprintf("「%s」磁盘 %s 空间不足", who, subject)
	}
	if en {
		return "A system resource is above its threshold"
	}
	return "系统资源超出阈值"
}

// HostGroupTitle names a merged system-status incident, for the same reason
// DegradationGroupTitle exists: the bare group name is already what a merged
// availability incident is called, and two identically-titled incidents — one
// meaning the group is unreachable, one meaning its machines are struggling —
// tell the reader nothing about either.
func HostGroupTitle(groupName, lang string) string {
	if lang == "en" {
		return fmt.Sprintf("System status in %q is abnormal", groupName)
	}
	return fmt.Sprintf("「%s」系统状态异常", groupName)
}

// TargetPortSuffix renders ":port" for a TCP-style target whose address does not
// already carry one. Signals freeze the port separately so a later config edit
// cannot rewrite the address the fault referred to.
func (s Signal) TargetPortSuffix() string {
	if s.Port <= 0 {
		return ""
	}
	for i := len(s.TargetAddr) - 1; i >= 0; i-- {
		if s.TargetAddr[i] == ':' {
			return ""
		}
		if s.TargetAddr[i] == ']' {
			break
		}
	}
	return fmt.Sprintf(":%d", s.Port)
}
