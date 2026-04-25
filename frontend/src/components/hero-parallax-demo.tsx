"use client";
import React from "react";
import { HeroParallax } from "./ui/hero-parallax";

export function HeroParallaxDemo() {
  return <HeroParallax products={products} />;
}
import {
  Bot,
  Radar,
  ShieldAlert,
  FileText,
  Globe2,
  DatabaseZap,
  Link2,
  Binary,
  ShieldCheck,
  Cpu,
  TimerReset,
  BadgeCheck,
  TrendingDown,
  Zap,
  Crosshair
} from "lucide-react";

export const products = [
  {
    title: "Autonomous Agents",
    description: "Crew-based AI agents continuously map attack surfaces, trigger scans, and adapt strategy to your infrastructure changes.",
    icon: <Bot size={48} className="text-cyan-400" />,
  },
  {
    title: "Continuous Scanning",
    description: "SentinelAI orchestrates scanner pipelines for web, network, and API layers so visibility stays fresh, not stale.",
    icon: <Radar size={48} className="text-emerald-400" />,
  },
  {
    title: "Risk-First Triage",
    description: "Findings are prioritized by exploitability and business impact so teams fix what matters first.",
    icon: <ShieldAlert size={48} className="text-rose-400" />,
  },
  {
    title: "Client Portal",
    description: "Give stakeholders clean dashboards, status tracking, and exportable reports without exposing internal complexity.",
    icon: <FileText size={48} className="text-indigo-400" />,
  },
  {
    title: "Global Asset Graph",
    description: "Domain, subdomain, and endpoint relationships are mapped into one living topology to expose hidden attack paths.",
    icon: <Globe2 size={48} className="text-blue-400" />,
  },
  {
    title: "Telemetry Fusion",
    description: "Scanner outputs, HTTP fingerprints, DNS traces, and contextual metadata are stitched into one signal stream.",
    icon: <DatabaseZap size={48} className="text-yellow-400" />,
  },
  {
    title: "Attack Chain Links",
    description: "Cross-finding correlation highlights escalation routes rather than isolated low-context findings.",
    icon: <Link2 size={48} className="text-fuchsia-400" />,
  },
  {
    title: "Policy As Logic",
    description: "Define guardrails once and let autonomous agents apply repeatable risk logic across every scan cycle.",
    icon: <Binary size={48} className="text-green-400" />,
  },
  {
    title: "Assurance Ledger",
    description: "Every action, severity change, and remediation state is tracked with timestamped audit evidence.",
    icon: <ShieldCheck size={48} className="text-teal-400" />,
  },
  {
    title: "Red Team Enablement",
    description: "Feed teams with constantly refreshed weak points before formal engagements begin.",
    icon: <Cpu size={48} className="text-purple-400" />,
  },
  {
    title: "Fast Regression",
    description: "Revalidate repaired vulnerabilities quickly after each deploy to prevent silent re-openings.",
    icon: <TimerReset size={48} className="text-orange-400" />,
  },
  {
    title: "Client-Facing",
    description: "Convert technical scan output into client-ready progress narratives with verifiable proof.",
    icon: <BadgeCheck size={48} className="text-sky-400" />,
  },
  {
    title: "81% Reduction",
    description: "False-positive reduction after AI correlation.",
    icon: <TrendingDown size={48} className="text-green-500" />,
  },
  {
    title: "3.2x Faster",
    description: "Time-to-priority reduction with risk-first triage.",
    icon: <Zap size={48} className="text-yellow-500" />,
  },
  {
    title: "94% Coverage",
    description: "Coverage consistency across repeat scan cycles.",
    icon: <Crosshair size={48} className="text-red-400" />,
  },
];
