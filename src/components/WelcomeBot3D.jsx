import React from 'react';

/**
 * WelcomeBot3D
 * An advanced, fully 3D rotating robot holding a mini holographic chat page.
 * Designed specifically for the chatbot welcome screen.
 */
export default function WelcomeBot3D() {
  return (
    <div className="welcome3d-wrapper">
      <style>{`
        .welcome3d-wrapper {
          width: 120px;
          height: 110px;
          margin: 0 auto;
          position: relative;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .welcome3d-scene {
          width: 100%;
          height: 100%;
          perspective: 600px;
          position: relative;
          transform-style: preserve-3d;
        }

        /* ── Rotating Container ───────────────── */
        .welcome3d-robot {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 0px;
          height: 0px;
          transform-style: preserve-3d;
          animation: welcomeBotAnim 10s linear infinite;
        }

        @keyframes welcomeBotAnim {
          0% {
            transform: scale(0.78) rotateY(0deg) rotateX(-12deg) translateY(0px);
          }
          50% {
            transform: scale(0.78) rotateY(180deg) rotateX(-12deg) translateY(-8px);
          }
          100% {
            transform: scale(0.78) rotateY(360deg) rotateX(-12deg) translateY(0px);
          }
        }

        /* ── Shared Face Styling ──────────────── */
        .welcome3d-robot .face {
          position: absolute;
          left: 50%;
          top: 50%;
          backface-visibility: hidden;
          border: 1px solid rgba(59, 130, 246, 0.35);
          box-shadow: inset 0 0 10px rgba(59, 130, 246, 0.15);
          border-radius: 4px;
          background: linear-gradient(135deg, #0f1a3a, #1a1040);
          transform-style: preserve-3d;
          box-sizing: border-box;
        }

        /* ── Head Cube ───────────────────────── */
        .welcome3d-head {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 60px;
          height: 50px;
          margin-left: -30px;
          margin-top: -55px;
          transform-style: preserve-3d;
        }

        .welcome3d-head .front {
          width: 60px;
          height: 50px;
          margin-left: -30px;
          margin-top: -25px;
          transform: translateZ(22px);
          background: linear-gradient(160deg, #162040, #0d1535);
        }

        .welcome3d-head .back {
          width: 60px;
          height: 50px;
          margin-left: -30px;
          margin-top: -25px;
          transform: translateZ(-22px) rotateY(180deg);
        }

        .welcome3d-head .left {
          width: 44px;
          height: 50px;
          margin-left: -22px;
          margin-top: -25px;
          transform: translateX(-30px) rotateY(-90deg);
        }

        .welcome3d-head .right {
          width: 44px;
          height: 50px;
          margin-left: -22px;
          margin-top: -25px;
          transform: translateX(30px) rotateY(90deg);
        }

        .welcome3d-head .top {
          width: 60px;
          height: 44px;
          margin-left: -30px;
          margin-top: -22px;
          transform: translateY(-25px) rotateX(90deg);
          background: linear-gradient(135deg, #0d1535, #1e1b4b);
        }

        .welcome3d-head .bottom {
          width: 60px;
          height: 44px;
          margin-left: -30px;
          margin-top: -22px;
          transform: translateY(25px) rotateX(-90deg);
        }

        /* ── Visor & Soundwave ───────────────── */
        .welcome3d-visor {
          width: 48px;
          height: 16px;
          background: rgba(6, 182, 212, 0.12);
          border: 1px solid rgba(6, 182, 212, 0.35);
          border-radius: 3px;
          position: absolute;
          top: 8px;
          left: 5px;
          overflow: hidden;
        }

        .welcome3d-eyestrip {
          width: 38px;
          height: 2px;
          background: #06b6d4;
          border-radius: 1px;
          position: absolute;
          top: 6px;
          left: 4px;
          box-shadow: 0 0 6px #06b6d4, 0 0 12px rgba(6, 182, 212, 0.8);
        }

        .welcome3d-scan-bar {
          width: 6px;
          height: 100%;
          background: rgba(255, 255, 255, 0.8);
          box-shadow: 0 0 6px #fff, 0 0 12px #06b6d4;
          position: absolute;
          top: 0;
          animation: scanBeam 2.5s ease-in-out infinite alternate;
        }

        @keyframes scanBeam {
          0%   { left: 0px; }
          100% { left: 42px; }
        }

        .welcome3d-voice-bars {
          display: flex;
          gap: 2px;
          position: absolute;
          bottom: 6px;
          left: 50%;
          transform: translateX(-50%);
        }

        .voice-bar {
          width: 2px;
          background: #06b6d4;
          border-radius: 1px;
          animation: voicePulse 0.8s ease-in-out infinite alternate;
        }

        .bar-1 { height: 5px; animation-delay: 0.1s; }
        .bar-2 { height: 9px; animation-delay: 0.25s; }
        .bar-3 { height: 13px; animation-delay: 0.4s; }
        .bar-4 { height: 7px; animation-delay: 0.15s; }
        .bar-5 { height: 11px; animation-delay: 0.3s; }

        @keyframes voicePulse {
          0%   { transform: scaleY(0.4); }
          100% { transform: scaleY(1.3); }
        }

        /* ── Back Reactor ───────────────────── */
        .welcome3d-reactor-outer {
          width: 26px;
          height: 26px;
          border-radius: 50%;
          border: 1.5px dashed #8b5cf6;
          position: absolute;
          left: 16px;
          top: 11px;
          animation: spinReactor 5s linear infinite;
        }

        .welcome3d-reactor-inner {
          width: 10px;
          height: 10px;
          border-radius: 50%;
          background: #8b5cf6;
          position: absolute;
          left: 6.5px;
          top: 6.5px;
          box-shadow: 0 0 10px #8b5cf6;
        }

        @keyframes spinReactor {
          0%   { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        /* ── Side Vents ─────────────────────── */
        .welcome3d-vents {
          width: 100%;
          height: 100%;
          padding: 6px;
          display: flex;
          flex-direction: column;
          justify-content: center;
          box-sizing: border-box;
        }

        .welcome3d-vent-line {
          width: 24px;
          height: 2px;
          background: rgba(59, 130, 246, 0.35);
          margin: 3px auto;
          border-radius: 1px;
        }

        /* ── Twin Antennas ─────────────────── */
        .welcome3d-twin-antennas {
          position: absolute;
          bottom: 0;
          left: 50%;
          transform: translateX(-50%) translateZ(-10px) rotateX(-90deg);
          display: flex;
          gap: 16px;
          transform-origin: bottom center;
        }

        .welcome-antenna {
          width: 2px;
          height: 12px;
          background: #6366f1;
          position: relative;
        }

        .welcome-antenna .tip {
          width: 4px;
          height: 4px;
          border-radius: 50%;
          background: #06b6d4;
          position: absolute;
          top: -4px;
          left: -1px;
          box-shadow: 0 0 6px #06b6d4;
          animation: antennaGlow 1.5s ease-in-out infinite alternate;
        }

        @keyframes antennaGlow {
          0%   { box-shadow: 0 0 4px #06b6d4; }
          100% { box-shadow: 0 0 10px #06b6d4, 0 0 15px rgba(6,182,212,0.8); }
        }

        /* ── Neck Cube ───────────────────────── */
        .welcome3d-neck {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 12px;
          height: 8px;
          margin-left: -6px;
          margin-top: -5px;
          transform-style: preserve-3d;
        }

        .welcome3d-neck .face {
          border-color: rgba(59, 130, 246, 0.25);
          box-shadow: inset 0 0 4px rgba(59, 130, 246, 0.1);
        }

        .welcome3d-neck .front {
          width: 12px;
          height: 8px;
          margin-left: -6px;
          margin-top: -4px;
          transform: translateZ(6px);
          background: #1e293b;
        }

        .welcome3d-neck .back {
          width: 12px;
          height: 8px;
          margin-left: -6px;
          margin-top: -4px;
          transform: translateZ(-6px) rotateY(180deg);
          background: #1e293b;
        }

        .welcome3d-neck .left {
          width: 12px;
          height: 8px;
          margin-left: -6px;
          margin-top: -4px;
          transform: translateX(-6px) rotateY(-90deg);
          background: #0f172a;
        }

        .welcome3d-neck .right {
          width: 12px;
          height: 8px;
          margin-left: -6px;
          margin-top: -4px;
          transform: translateX(6px) rotateY(90deg);
          background: #0f172a;
        }

        .welcome3d-neck .top {
          width: 12px;
          height: 12px;
          margin-left: -6px;
          margin-top: -6px;
          transform: translateY(-4px) rotateX(90deg);
          background: #0f172a;
        }

        .welcome3d-neck .bottom {
          width: 12px;
          height: 12px;
          margin-left: -6px;
          margin-top: -6px;
          transform: translateY(4px) rotateX(-90deg);
          background: #0f172a;
        }

        /* ── Body Cube ───────────────────────── */
        .welcome3d-body {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 48px;
          height: 30px;
          margin-left: -24px;
          margin-top: 3px;
          transform-style: preserve-3d;
        }

        .welcome3d-body .front {
          width: 48px;
          height: 30px;
          margin-left: -24px;
          margin-top: -15px;
          transform: translateZ(17px);
          background: linear-gradient(160deg, #162040, #0d1535);
        }

        .welcome3d-body .back {
          width: 48px;
          height: 30px;
          margin-left: -24px;
          margin-top: -15px;
          transform: translateZ(-17px) rotateY(180deg);
        }

        .welcome3d-body .left {
          width: 34px;
          height: 30px;
          margin-left: -17px;
          margin-top: -15px;
          transform: translateX(-24px) rotateY(-90deg);
        }

        .welcome3d-body .right {
          width: 34px;
          height: 30px;
          margin-left: -17px;
          margin-top: -15px;
          transform: translateX(24px) rotateY(90deg);
        }

        .welcome3d-body .top {
          width: 48px;
          height: 34px;
          margin-left: -24px;
          margin-top: -17px;
          transform: translateY(-15px) rotateX(90deg);
        }

        .welcome3d-body .bottom {
          width: 48px;
          height: 34px;
          margin-left: -24px;
          margin-top: -17px;
          transform: translateY(15px) rotateX(-90deg);
        }

        /* ── Chest Reactor ──────────────────── */
        .welcome3d-chest-reactor {
          width: 10px;
          height: 10px;
          border-radius: 50%;
          background: #06b6d4;
          box-shadow: 0 0 8px #06b6d4, 0 0 15px rgba(6,182,212,0.6);
          position: absolute;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          animation: chestPulse 2s ease-in-out infinite alternate;
        }

        @keyframes chestPulse {
          0%   { opacity: 0.6; box-shadow: 0 0 5px #06b6d4; }
          100% { opacity: 1; box-shadow: 0 0 10px #06b6d4, 0 0 18px rgba(6,182,212,0.8); }
        }

        /* ── Arms & Screen ───────────────────── */
        .welcome3d-arm {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 8px;
          height: 8px;
          transform-style: preserve-3d;
        }

        .welcome3d-arm-left {
          margin-left: -28px;
          margin-top: -4px;
          transform: translateY(12px) translateZ(10px) rotateY(25deg) rotateX(5deg);
        }

        .welcome3d-arm-right {
          margin-left: 20px;
          margin-top: -4px;
          transform: translateY(12px) translateZ(10px) rotateY(-25deg) rotateX(5deg);
        }

        .welcome3d-arm .face {
          border-color: rgba(59, 130, 246, 0.3);
          box-shadow: inset 0 0 4px rgba(59, 130, 246, 0.1);
        }

        .welcome3d-arm .front {
          width: 8px;
          height: 8px;
          margin-left: -4px;
          margin-top: -4px;
          transform: translateZ(10px);
          background: #1e293b;
        }

        .welcome3d-arm .back {
          width: 8px;
          height: 8px;
          margin-left: -4px;
          margin-top: -4px;
          transform: translateZ(-10px) rotateY(180deg);
          background: #1e293b;
        }

        .welcome3d-arm .left {
          width: 20px;
          height: 8px;
          margin-left: -10px;
          margin-top: -4px;
          transform: translateX(-4px) rotateY(-90deg);
          background: #0f172a;
        }

        .welcome3d-arm .right {
          width: 20px;
          height: 8px;
          margin-left: -10px;
          margin-top: -4px;
          transform: translateX(4px) rotateY(90deg);
          background: #0f172a;
        }

        .welcome3d-arm .top {
          width: 8px;
          height: 20px;
          margin-left: -4px;
          margin-top: -10px;
          transform: translateY(-4px) rotateX(90deg);
          background: #0f172a;
        }

        .welcome3d-arm .bottom {
          width: 8px;
          height: 20px;
          margin-left: -4px;
          margin-top: -10px;
          transform: translateY(4px) rotateX(-90deg);
          background: #0f172a;
        }

        /* ── Holographic Held Screen ──────── */
        .welcome3d-held-screen {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 54px;
          height: 38px;
          margin-left: -27px;
          margin-top: -19px;
          transform: translateY(12px) translateZ(24px) rotateX(-15deg);
          background: rgba(6, 182, 212, 0.15);
          border: 1.5px solid rgba(6, 182, 212, 0.6);
          box-shadow: 0 0 15px rgba(6, 182, 212, 0.4), inset 0 0 10px rgba(6, 182, 212, 0.2);
          border-radius: 4px;
          transform-style: preserve-3d;
          box-sizing: border-box;
          padding: 3px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          backface-visibility: hidden;
        }

        .welcome3d-mini-chat {
          display: flex;
          flex-direction: column;
          gap: 2.5px;
        }

        .welcome3d-mini-header {
          font-family: 'Inter', sans-serif;
          font-size: 5px;
          font-weight: 700;
          color: #06b6d4;
          text-align: center;
          text-shadow: 0 0 3px rgba(6,182,212,0.8);
          border-bottom: 0.5px solid rgba(6, 182, 212, 0.3);
          padding-bottom: 1px;
          margin-bottom: 1px;
          line-height: 1;
        }

        .welcome3d-mini-bubble-left {
          width: 26px;
          height: 2px;
          background: rgba(255, 255, 255, 0.6);
          box-shadow: 0 0 3px rgba(255,255,255,0.4);
          border-radius: 1px;
          margin-left: 1px;
        }

        .welcome3d-mini-bubble-right {
          width: 18px;
          height: 2px;
          background: rgba(6, 182, 212, 0.75);
          box-shadow: 0 0 4px rgba(6,182,212,0.6);
          border-radius: 1px;
          margin-left: auto;
          margin-right: 1px;
        }

        .welcome3d-mini-input {
          width: 100%;
          height: 4px;
          background: rgba(255, 255, 255, 0.15);
          border: 0.5px solid rgba(6, 182, 212, 0.4);
          border-radius: 1px;
          display: flex;
          align-items: center;
          padding-left: 2px;
          box-sizing: border-box;
        }

        .welcome3d-mini-cursor {
          width: 1.5px;
          height: 2px;
          background: #06b6d4;
          animation: miniBlink 1s infinite alternate;
        }

        @keyframes miniBlink {
          0% { opacity: 0.2; }
          100% { opacity: 1; }
        }

        /* ── Jet Thruster ──────────────────── */
        .welcome3d-thruster {
          width: 16px;
          height: 16px;
          border-radius: 50%;
          background: radial-gradient(circle, #3b82f6 30%, transparent 70%);
          border: 1px solid rgba(59, 130, 246, 0.4);
          box-shadow: 0 0 10px #3b82f6;
          position: absolute;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
        }

        /* ── Holographic Ring ────────────────── */
        .welcome3d-ring {
          position: absolute;
          width: 90px;
          height: 90px;
          margin-left: -45px;
          margin-top: -45px;
          border: 1.5px dashed rgba(6, 182, 212, 0.5);
          border-radius: 50%;
          transform-style: preserve-3d;
          box-shadow: 0 0 15px rgba(6, 182, 212, 0.15), inset 0 0 15px rgba(6, 182, 212, 0.15);
          animation: ringSpin 8s linear infinite;
          pointer-events: none;
        }

        @keyframes ringSpin {
          0% { transform: translateY(18px) rotateX(85deg) rotateZ(0deg); }
          100% { transform: translateY(18px) rotateX(85deg) rotateZ(-360deg); }
        }

        /* ── Ground Aura ───────────────────── */
        .welcome3d-aura {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 60px;
          height: 8px;
          margin-left: -30px;
          margin-top: 48px;
          background: radial-gradient(ellipse, rgba(59, 130, 246, 0.5) 0%, transparent 70%);
          filter: blur(6px);
          animation: welcomeAura 4s ease-in-out infinite;
        }

        @keyframes welcomeAura {
          0%, 100% { transform: scaleX(1); opacity: 0.6; }
          50%      { transform: scaleX(0.75); opacity: 0.3; }
        }
      `}</style>

      <div className="welcome3d-scene">
        <div className="welcome3d-robot">
          {/* Head Cube */}
          <div className="welcome3d-head">
            <div className="face front">
              <div className="welcome3d-visor">
                <div className="welcome3d-eyestrip"></div>
                <div className="welcome3d-scan-bar"></div>
              </div>
              <div className="welcome3d-voice-bars">
                <div className="voice-bar bar-1"></div>
                <div className="voice-bar bar-2"></div>
                <div className="voice-bar bar-3"></div>
                <div className="voice-bar bar-4"></div>
                <div className="voice-bar bar-5"></div>
              </div>
            </div>
            <div className="face back">
              <div className="welcome3d-reactor-outer">
                <div className="welcome3d-reactor-inner"></div>
              </div>
            </div>
            <div className="face left">
              <div className="welcome3d-vents">
                <div className="welcome3d-vent-line"></div>
                <div className="welcome3d-vent-line"></div>
                <div className="welcome3d-vent-line"></div>
              </div>
            </div>
            <div className="face right">
              <div className="welcome3d-vents">
                <div className="welcome3d-vent-line"></div>
                <div className="welcome3d-vent-line"></div>
                <div className="welcome3d-vent-line"></div>
              </div>
            </div>
            <div className="face top">
              <div className="welcome3d-twin-antennas">
                <div className="welcome-antenna ant-left">
                  <div className="tip"></div>
                </div>
                <div className="welcome-antenna ant-right">
                  <div className="tip"></div>
                </div>
              </div>
            </div>
            <div className="face bottom"></div>
          </div>

          {/* Neck Cube */}
          <div className="welcome3d-neck">
            <div className="face front"></div>
            <div className="face back"></div>
            <div className="face left"></div>
            <div className="face right"></div>
            <div className="face top"></div>
            <div className="face bottom"></div>
          </div>

          {/* Body Cube */}
          <div className="welcome3d-body">
            <div className="face front">
              <div className="welcome3d-chest-reactor"></div>
            </div>
            <div className="face back"></div>
            <div className="face left">
              <div className="welcome3d-vents">
                <div className="welcome3d-vent-line"></div>
                <div className="welcome3d-vent-line"></div>
              </div>
            </div>
            <div className="face right">
              <div className="welcome3d-vents">
                <div className="welcome3d-vent-line"></div>
                <div className="welcome3d-vent-line"></div>
              </div>
            </div>
            <div className="face top"></div>
            <div className="face bottom">
              <div className="welcome3d-thruster"></div>
            </div>
          </div>

          {/* Left Arm */}
          <div className="welcome3d-arm welcome3d-arm-left">
            <div className="face front"></div>
            <div className="face back"></div>
            <div className="face left"></div>
            <div className="face right"></div>
            <div className="face top"></div>
            <div className="face bottom"></div>
          </div>

          {/* Right Arm */}
          <div className="welcome3d-arm welcome3d-arm-right">
            <div className="face front"></div>
            <div className="face back"></div>
            <div className="face left"></div>
            <div className="face right"></div>
            <div className="face top"></div>
            <div className="face bottom"></div>
          </div>

          {/* Held Holographic Screen */}
          <div className="welcome3d-held-screen">
            <div className="welcome3d-mini-chat">
              <div className="welcome3d-mini-header">StackDrive</div>
              <div className="welcome3d-mini-bubble-left"></div>
              <div className="welcome3d-mini-bubble-right"></div>
            </div>
            <div className="welcome3d-mini-input">
              <div className="welcome3d-mini-cursor"></div>
            </div>
          </div>

          {/* Holographic Ring */}
          <div className="welcome3d-ring"></div>
        </div>

        {/* Shadow Aura */}
        <div className="welcome3d-aura"></div>
      </div>
    </div>
  );
}
