"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  Terminal,
  Play,
  RefreshCw,
  Printer,
  Server,
  Lock,
  Radio,
  Clock,
  Database,
  Volume2,
  VolumeX,
  FileText,
  CheckCircle2,
  Activity,
  Layers,
  ArrowRight,
  SlidersHorizontal,
  ChevronRight
} from "lucide-react";
import ReactMarkdown from "react-markdown";

class CyberAudio {
  private ctx: AudioContext | null = null;
  public enabled: boolean = true;

  private getCtx() {
    if (!this.ctx && typeof window !== "undefined") {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === "suspended") this.ctx.resume();
    return this.ctx;
  }

  playBlip(freq = 1100, duration = 0.02) {
    if (!this.enabled) return;
    try {
      const ctx = this.getCtx();
      if (!ctx) return;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch {}
  }
}

const audioFX = new CyberAudio();

interface SecurityAlert {
  alert_id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  target_host: string;
  user: string;
  event_type: string;
  raw_severity: "CRITICAL" | "HIGH" | "LOW";
  asset_criticality: "TIER_1_CROWN_JEWEL" | "TIER_3_DEV";
  description: string;
  mitre_tactic: string;
  mitre_id: string;
}

interface StepEvent {
  agent_name: string;
  stage: string;
  message: string;
}

const DEFAULT_ALERTS: SecurityAlert[] = [
  {
    alert_id: "ALT-1001",
    timestamp: "13:45:00 UTC",
    source_ip: "194.26.29.112",
    dest_ip: "10.0.4.12",
    target_host: "DC-PROD-01",
    user: "svc_backup",
    event_type: "Kerberos Pre-Auth Spraying (x480)",
    raw_severity: "HIGH",
    asset_criticality: "TIER_1_CROWN_JEWEL",
    description: "High rate of pre-authentication failures detected across domain controller Kerberos interface.",
    mitre_tactic: "Initial Access",
    mitre_id: "T1110.003"
  },
  {
    alert_id: "ALT-1002",
    timestamp: "13:48:12 UTC",
    source_ip: "194.26.29.112",
    dest_ip: "10.0.4.12",
    target_host: "DC-PROD-01",
    user: "svc_backup",
    event_type: "Logon Type 3 Auth Validation",
    raw_severity: "CRITICAL",
    asset_criticality: "TIER_1_CROWN_JEWEL",
    description: "Successful logon from external malicious IP following password spraying cluster.",
    mitre_tactic: "Initial Access",
    mitre_id: "T1078.002"
  },
  {
    alert_id: "ALT-1003",
    timestamp: "13:51:04 UTC",
    source_ip: "10.0.4.12",
    dest_ip: "10.0.8.50",
    target_host: "DB-CUSTOMER-SQL",
    user: "svc_backup",
    event_type: "PowerShell -EncodedCommand (SAM Dump)",
    raw_severity: "HIGH",
    asset_criticality: "TIER_1_CROWN_JEWEL",
    description: "Extraction of hashed registry credentials and memory database connection strings.",
    mitre_tactic: "Execution",
    mitre_id: "T1059.001"
  },
  {
    alert_id: "ALT-1004",
    timestamp: "13:55:20 UTC",
    source_ip: "10.0.8.50",
    dest_ip: "85.204.11.8",
    target_host: "DB-CUSTOMER-SQL",
    user: "svc_backup",
    event_type: "Anomalous Egress Flow (4.2 GB)",
    raw_severity: "CRITICAL",
    asset_criticality: "TIER_1_CROWN_JEWEL",
    description: "High-volume encrypted outbound transfer egressing to external C2 drop server.",
    mitre_tactic: "Exfiltration",
    mitre_id: "T1041"
  },
  {
    alert_id: "ALT-1005",
    timestamp: "13:58:00 UTC",
    source_ip: "10.0.99.14",
    dest_ip: "10.0.99.2",
    target_host: "DEV-TEST-VM",
    user: "intern_dev",
    event_type: "TCP SYN Sweep (Ports 1-1024)",
    raw_severity: "LOW",
    asset_criticality: "TIER_3_DEV",
    description: "Developer sandbox service discovery scan. Correlated as benign operational testing.",
    mitre_tactic: "Reconnaissance",
    mitre_id: "T1595.001"
  },
];

export default function LinearPrecisionSOC() {
  const [alerts] = useState<SecurityAlert[]>(DEFAULT_ALERTS);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert>(DEFAULT_ALERTS[1]);
  const [loading, setLoading] = useState<boolean>(false);
  const [activeStage, setActiveStage] = useState<string>("SYSTEM READY");
  const [events, setEvents] = useState<StepEvent[]>([]);
  const [finalReport, setFinalReport] = useState<string>("");
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);

  // Containment Switches
  const [hostIsolated, setHostIsolated] = useState<boolean>(false);
  const [tokenRevoked, setTokenRevoked] = useState<boolean>(false);
  const [ipBlocked, setIpBlocked] = useState<boolean>(false);

  const toggleSound = () => {
    audioFX.enabled = !soundEnabled;
    setSoundEnabled(!soundEnabled);
    if (!soundEnabled) audioFX.playBlip(1200);
  };

  const handleTriage = async () => {
    audioFX.playBlip(1300);
    setLoading(true);
    setEvents([]);
    setFinalReport("");
    setActiveStage("ORCHESTRATING AGENTS");

    const backendUrl = process.env.NEXT_PUBLIC_API_URL || "https://sentinel-soc-rjc4.onrender.com";

    try {
      const response = await fetch(`${backendUrl}/api/triage/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          analyst_notes: "Tier-1 Autonomous Handover Audit",
          alerts: alerts,
        }),
      });

      if (!response.body) throw new Error("Stream connection failed.");

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const dataStr = line.replace("data: ", "").trim();
            if (!dataStr) continue;

            try {
              const parsed: StepEvent = JSON.parse(dataStr);
              setEvents((prev) => [...prev, parsed]);
              setActiveStage(`${parsed.agent_name.toUpperCase()}`);
              audioFX.playBlip(950);

              if (parsed.agent_name === "IncidentCommanderAgent" && parsed.stage === "COMPLETE") {
                setFinalReport(parsed.message);
                setActiveStage("AUDIT RATIFIED");
                audioFX.playBlip(1400);
              }
            } catch (err) {
              console.error("Stream parse error:", err);
            }
          }
        }
      }
    } catch (err) {
      console.error("Execution error:", err);
      setActiveStage("DISPATCH FAILED");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen desk-canvas text-[#F8FAFC] font-sans antialiased text-xs flex flex-col">
      
      {/* 1. Header Toolbar */}
      <header className="h-12 border-b border-[#1A1D26] bg-[#0A0B0E]/85 backdrop-blur-xl px-5 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center space-x-5">
          <div className="flex items-center space-x-2.5">
            <div className="w-6 h-6 rounded bg-[#13151D] border border-[#232735] flex items-center justify-center">
              <ShieldAlert className="w-3.5 h-3.5 text-white" />
            </div>
            <span className="font-semibold text-xs tracking-tight text-white">
              Sentinel Triage <span className="text-[#64748B] font-normal">/ Problem #25</span>
            </span>
          </div>

          <div className="h-3.5 w-[1px] bg-[#1E222D]" />

          <div className="hidden md:flex items-center space-x-4 text-[#94A3B8] text-[11px] font-mono">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              TELEMETRY: CONNECTED
            </span>
            <span>MODEL: GEMINI-2.5-FLASH</span>
            <span>MTTT REDUCTION: <strong className="text-emerald-400">98.1%</strong></span>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={toggleSound}
            className="p-1.5 rounded border border-[#1A1D26] bg-[#0E1015] hover:bg-[#161822] text-[#94A3B8] hover:text-white transition"
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5 text-[#475569]" />}
          </button>

          <div className="px-2.5 py-1 rounded bg-[#0E1015] border border-[#1A1D26] text-[10px] font-mono text-[#94A3B8]">
            {activeStage}
          </div>

          <button
            onClick={handleTriage}
            disabled={loading}
            className="flex items-center gap-1.5 bg-white hover:bg-slate-200 disabled:bg-[#1A1D26] text-slate-950 disabled:text-[#64748B] font-semibold px-3 py-1 rounded transition text-[11px] cursor-pointer"
          >
            {loading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-current" />}
            <span>Execute Autonomous Triage</span>
          </button>

          {finalReport && (
            <button
              onClick={() => window.print()}
              className="p-1.5 rounded border border-[#1A1D26] bg-[#0E1015] hover:bg-[#161822] text-[#94A3B8] hover:text-white transition"
              title="Print Dossier"
            >
              <Printer className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </header>

      {/* 2. Main Workstation Area: Master-Detail Split */}
      <div className="flex-1 flex overflow-hidden">

        {/* LEFT PANE: Precision Telemetry Table (56% width) */}
        <div className="w-[56%] border-r border-[#1A1D26] flex flex-col bg-[#08090C]/90 backdrop-blur-md">
          
          <div className="h-9 px-4 border-b border-[#1A1D26] flex items-center justify-between text-[#64748B] text-[11px] font-mono">
            <span>INCOMING TELEMETRY STREAM ({alerts.length})</span>
            <span>SELECT ROW TO INSPECT FORENSICS</span>
          </div>

          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#1A1D26] text-[10px] font-mono uppercase text-[#64748B] bg-[#0D0E13]/80 sticky top-0">
                  <th className="py-2 px-4 font-normal">Severity</th>
                  <th className="py-2 px-3 font-normal">Timestamp</th>
                  <th className="py-2 px-3 font-normal">Target Asset</th>
                  <th className="py-2 px-3 font-normal">Event Type</th>
                  <th className="py-2 px-3 font-normal">MITRE TTP</th>
                  <th className="py-2 px-4 font-normal text-right">User</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1D26] font-mono text-[11px]">
                {alerts.map((a) => {
                  const isSelected = selectedAlert.alert_id === a.alert_id;
                  return (
                    <tr
                      key={a.alert_id}
                      onClick={() => {
                        audioFX.playBlip(850);
                        setSelectedAlert(a);
                      }}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? "bg-[#141722] text-white" : "hover:bg-[#0E1017] text-[#CBD5E1]"
                      }`}
                    >
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 font-sans font-medium text-[10px] px-1.5 py-0.5 rounded ${
                          a.raw_severity === "CRITICAL"
                            ? "bg-red-500/10 text-red-400 border border-red-500/20"
                            : a.raw_severity === "HIGH"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                            : "bg-slate-800 text-slate-400"
                        }`}>
                          <span className={`w-1 h-1 rounded-full ${a.raw_severity === "CRITICAL" ? "bg-red-400" : a.raw_severity === "HIGH" ? "bg-amber-400" : "bg-slate-400"}`} />
                          {a.raw_severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-[#64748B] whitespace-nowrap">{a.timestamp}</td>
                      <td className="py-2.5 px-3 font-semibold text-white whitespace-nowrap">{a.target_host}</td>
                      <td className="py-2.5 px-3 font-sans truncate max-w-[210px]" title={a.event_type}>
                        {a.event_type}
                      </td>
                      <td className="py-2.5 px-3 text-[#94A3B8] whitespace-nowrap">{a.mitre_id}</td>
                      <td className="py-2.5 px-4 text-right text-[#64748B] whitespace-nowrap">{a.user}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {/* Embedded Supervisory Agent Stream */}
            <div className="p-4 border-t border-[#1A1D26] bg-[#0A0B0E]/60 mt-4">
              <div className="flex items-center justify-between text-[#64748B] text-[10px] font-mono uppercase mb-2">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3 h-3 text-[#94A3B8]" /> Autonomous Supervisory Log
                </span>
                <span>{events.length} ACTIONS RECORDED</span>
              </div>

              {events.length === 0 ? (
                <div className="py-6 text-center text-[#475569] font-mono text-[11px] border border-dashed border-[#1A1D26] rounded">
                  System waiting. Click &ldquo;Execute Autonomous Triage&rdquo; to dispatch agent cluster.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-36 overflow-y-auto font-mono text-[11px]">
                  {events.map((evt, idx) => (
                    <div key={idx} className="flex items-baseline gap-2 py-1 px-2 rounded bg-[#0D0E14] border border-[#1A1D26]">
                      <span className="text-amber-400 font-bold shrink-0">[{evt.agent_name}]</span>
                      <span className="text-[#94A3B8] truncate">{evt.message}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT PANE: Forensic Inspector & Shift Dossier (44% width) */}
        <div className="w-[44%] flex flex-col bg-[#0B0C10]/95 backdrop-blur-md overflow-y-auto">
          
          <div className="h-9 px-4 border-b border-[#1A1D26] flex items-center justify-between text-[#64748B] text-[11px] font-mono">
            <span>FORENSIC INSPECTION // {selectedAlert.alert_id}</span>
            <span className="text-amber-400">{selectedAlert.asset_criticality}</span>
          </div>

          <div className="p-5 space-y-5">
            
            {/* 1. Alert Forensic Detail Card */}
            <div className="p-4 rounded-lg bg-[#0F1118] border border-[#1E222D] space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-white">{selectedAlert.event_type}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161822] text-slate-300 border border-[#232735]">
                  {selectedAlert.mitre_tactic} ({selectedAlert.mitre_id})
                </span>
              </div>
              <p className="text-[#94A3B8] text-xs leading-relaxed font-sans">
                {selectedAlert.description}
              </p>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#1A1D26] font-mono text-[11px] text-[#94A3B8]">
                <div>SOURCE: <span className="text-white">{selectedAlert.source_ip}</span></div>
                <div>DESTINATION: <span className="text-white">{selectedAlert.dest_ip}</span></div>
                <div>AFFECTED HOST: <span className="text-white">{selectedAlert.target_host}</span></div>
                <div>IDENTITY: <span className="text-white">{selectedAlert.user}</span></div>
              </div>
            </div>

            {/* 2. Zero-Trust Containment Directives */}
            <div className="space-y-2">
              <span className="text-[10px] font-mono uppercase text-[#64748B] block tracking-wider">
                Human-in-the-Loop Quarantine Ratification
              </span>
              <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
                <button
                  onClick={() => {
                    audioFX.playBlip(1200);
                    setHostIsolated(!hostIsolated);
                  }}
                  className={`p-2.5 rounded border transition cursor-pointer text-left ${
                    hostIsolated
                      ? "bg-red-500/10 border-red-500/40 text-red-300"
                      : "bg-[#0F1118] border-[#1E222D] hover:border-[#33394B] text-[#CBD5E1]"
                  }`}
                >
                  <div className="text-[9px] text-[#64748B]">TARGET HOST</div>
                  <div className="font-semibold text-white truncate">{selectedAlert.target_host}</div>
                  <div className="text-[9px] mt-1 text-red-400 font-bold">
                    {hostIsolated ? "ISOLATED" : "ISOLATE HOST"}
                  </div>
                </button>

                <button
                  onClick={() => {
                    audioFX.playBlip(1200);
                    setTokenRevoked(!tokenRevoked);
                  }}
                  className={`p-2.5 rounded border transition cursor-pointer text-left ${
                    tokenRevoked
                      ? "bg-amber-500/10 border-amber-500/40 text-amber-300"
                      : "bg-[#0F1118] border-[#1E222D] hover:border-[#33394B] text-[#CBD5E1]"
                  }`}
                >
                  <div className="text-[9px] text-[#64748B]">CREDENTIAL</div>
                  <div className="font-semibold text-white truncate">{selectedAlert.user}</div>
                  <div className="text-[9px] mt-1 text-amber-400 font-bold">
                    {tokenRevoked ? "REVOKED" : "REVOKE TOKEN"}
                  </div>
                </button>

                <button
                  onClick={() => {
                    audioFX.playBlip(1200);
                    setIpBlocked(!ipBlocked);
                  }}
                  className={`p-2.5 rounded border transition cursor-pointer text-left ${
                    ipBlocked
                      ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                      : "bg-[#0F1118] border-[#1E222D] hover:border-[#33394B] text-[#CBD5E1]"
                  }`}
                >
                  <div className="text-[9px] text-[#64748B]">INGRESS IP</div>
                  <div className="font-semibold text-white truncate">{selectedAlert.source_ip}</div>
                  <div className="text-[9px] mt-1 text-emerald-400 font-bold">
                    {ipBlocked ? "BLOCKED" : "BLOCK IP"}
                  </div>
                </button>
              </div>
            </div>

            {/* 3. Formal Markdown Shift Dossier */}
            <div className="space-y-2 pt-2 border-t border-[#1A1D26]">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase text-[#64748B] tracking-wider">
                  Tier-1 Autonomous Handover Dossier
                </span>
                {finalReport && (
                  <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> VERIFIED
                  </span>
                )}
              </div>

              {finalReport ? (
                <div className="p-4 rounded-lg bg-[#0F1118] border border-[#1E222D] prose prose-invert max-w-none text-[#CBD5E1] text-xs leading-relaxed font-sans">
                  <ReactMarkdown>{finalReport}</ReactMarkdown>
                </div>
              ) : (
                <div className="p-8 text-center rounded-lg border border-dashed border-[#1E222D] text-[#64748B] space-y-1">
                  <FileText className="w-5 h-5 mx-auto text-[#475569]" />
                  <div className="font-mono text-[11px] text-[#94A3B8]">No Incident Brief Generated</div>
                  <div className="text-[11px] text-[#64748B] font-sans">
                    Execute autonomous triage to correlate alerts against MITRE ATT&amp;CK and generate the executive brief.
                  </div>
                </div>
              )}
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}