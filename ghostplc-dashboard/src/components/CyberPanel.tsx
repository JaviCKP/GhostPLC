import { ReactNode } from "react";

interface CyberPanelProps {
  children: ReactNode;
  className?: string;
  variant?: "emerald" | "cyan" | "orange" | "neutral";
}

export function CyberPanel({ children, className = "", variant = "emerald" }: CyberPanelProps) {
  const themes = {
    emerald: "border-emerald-500/20 shadow-[inset_0_0_20px_rgba(16,185,129,0.02)]",
    cyan: "border-cyan-500/20 shadow-[inset_0_0_20px_rgba(6,182,212,0.02)]",
    orange: "border-orange-500/20 shadow-[inset_0_0_20px_rgba(249,115,22,0.02)]",
    neutral: "border-white/10",
  };

  const cornerThemes = {
    emerald: "border-emerald-500/70",
    cyan: "border-cyan-500/70",
    orange: "border-orange-500/70",
    neutral: "border-white/30",
  };

  const themeBorder = themes[variant];
  const themeCorner = cornerThemes[variant];

  return (
    <section
      className={`pointer-events-auto relative select-none rounded-lg border bg-[#040706]/80 shadow-2xl shadow-black/50 backdrop-blur-md ${themeBorder} ${className}`}
    >
      {/* Esquinas minimalistas */}
      <div className={`pointer-events-none absolute -left-[1px] -top-[1px] h-2.5 w-2.5 rounded-tl-lg border-l-2 border-t-2 ${themeCorner}`} />
      <div className={`pointer-events-none absolute -right-[1px] -top-[1px] h-2.5 w-2.5 rounded-tr-lg border-r-2 border-t-2 ${themeCorner}`} />
      <div className={`pointer-events-none absolute -bottom-[1px] -left-[1px] h-2.5 w-2.5 rounded-bl-lg border-b-2 border-l-2 ${themeCorner}`} />
      <div className={`pointer-events-none absolute -bottom-[1px] -right-[1px] h-2.5 w-2.5 rounded-br-lg border-b-2 border-r-2 ${themeCorner}`} />

      {children}
    </section>
  );
}
