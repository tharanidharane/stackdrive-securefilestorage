import React from 'react';

/**
 * CopilotBot3D
 * Renders a small, interactive 3D robot head using CSS 3D transforms.
 * Fully self-contained and portable with scoped styles.
 */
export default function CopilotBot3D({ onClick, isOpen }) {
  return (
    <div className={`bot3d-wrapper ${isOpen ? 'is-open' : ''}`} onClick={onClick}>
      <style>{`
        .bot3d-wrapper {
          position: fixed;
          bottom: 28px;
          right: 28px;
          z-index: 1000;
          width: 58px;
          height: 58px;
          cursor: pointer;
          user-select: none;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1), transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .bot3d-wrapper.is-open {
          opacity: 0;
          pointer-events: none;
          transform: scale(0.6) translateY(20px);
        }

        .bot3d-container {
          position: relative;
          width: 100%;
          height: 100%;
        }

        /* ── Scene & Wrapper ──────────────── */
        .bot3d-scene-wrapper {
          width: 100%;
          height: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s ease;
        }

        .bot3d-scene {
          width: 58px;
          height: 58px;
          perspective: 500px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          position: relative;
          animation: bot3dFloat 3.5s ease-in-out infinite;
        }

        @keyframes bot3dFloat {
          0%, 100% { transform: translateY(0); }
          50%      { transform: translateY(-5px); }
        }

        /* ── Robot Group ─────────────────── */
        .bot3d-robot {
          transform-style: preserve-3d;
          animation: botIdleRock 5s ease-in-out infinite;
          transition: transform 0.4s ease;
          position: relative;
          display: flex;
          flex-direction: column;
          align-items: center;
          filter: drop-shadow(0 0 10px rgba(6, 182, 212, 0.45));
        }

        @keyframes botIdleRock {
          0%, 100% { transform: rotateY(-6deg) rotateX(2deg); }
          50%      { transform: rotateY(6deg) rotateX(-2deg); }
        }

        .bot3d-scene:hover .bot3d-robot {
          transform: rotateY(22deg) rotateX(-12deg) scale(1.08);
          animation-play-state: paused;
        }

        /* ── Head Cube ───────────────────── */
        .bot3d-head {
          transform-style: preserve-3d;
          position: relative;
          width: 44px;
          height: 38px;
        }

        .bot3d-head .face {
          position: absolute;
          left: 50%;
          top: 50%;
          backface-visibility: hidden;
          border: 1.5px solid rgba(59, 130, 246, 0.70);
          box-shadow: inset 0 0 10px rgba(59, 130, 246, 0.25);
          border-radius: 4px;
          background: linear-gradient(135deg, #16264f, #231244);
          transform-style: preserve-3d;
          box-sizing: border-box;
        }

        .bot3d-head .front {
          width: 44px;
          height: 38px;
          margin-left: -22px;
          margin-top: -19px;
          transform: translateZ(16px);
          background: linear-gradient(160deg, #1a2a5e, #101c42);
        }

        .bot3d-head .back {
          width: 44px;
          height: 38px;
          margin-left: -22px;
          margin-top: -19px;
          transform: translateZ(-16px) rotateY(180deg);
        }

        .bot3d-head .left {
          width: 32px;
          height: 38px;
          margin-left: -16px;
          margin-top: -19px;
          transform: translateX(-22px) rotateY(-90deg);
        }

        .bot3d-head .right {
          width: 32px;
          height: 38px;
          margin-left: -16px;
          margin-top: -19px;
          transform: translateX(22px) rotateY(90deg);
        }

        .bot3d-head .top {
          width: 44px;
          height: 32px;
          margin-left: -22px;
          margin-top: -16px;
          transform: translateY(-19px) rotateX(90deg);
          background: linear-gradient(135deg, #0d1535, #1e1b4b);
        }

        .bot3d-head .bottom {
          width: 44px;
          height: 32px;
          margin-left: -22px;
          margin-top: -16px;
          transform: translateY(19px) rotateX(-90deg);
        }

        /* ── Front Face Details ───────────── */
        .bot3d-eye {
          width: 12px;
          height: 4px;
          border-radius: 2px;
          background: #06b6d4;
          box-shadow: 0 0 10px #06b6d4, 0 0 20px rgba(6, 182, 212, 0.8);
          position: absolute;
          top: 11px;
          animation: eyePulse 2s ease-in-out infinite;
        }

        .bot3d-eye-left {
          left: 8px;
        }

        .bot3d-eye-right {
          right: 8px;
          animation-delay: 0.3s;
        }

        @keyframes eyePulse {
          0%, 100% {
            opacity: 1;
            box-shadow: 0 0 10px #06b6d4, 0 0 20px rgba(6, 182, 212, 0.95);
          }
          50% {
            opacity: 0.5;
            box-shadow: 0 0 5px #06b6d4, 0 0 10px rgba(6, 182, 212, 0.5);
          }
        }

        .bot3d-mouth {
          display: flex;
          gap: 3px;
          position: absolute;
          bottom: 9px;
          left: 50%;
          transform: translateX(-50%);
        }

        .bot3d-mouth-dot {
          width: 3px;
          height: 2px;
          border-radius: 0.5px;
          background: #06b6d4;
          box-shadow: 0 0 4px #06b6d4;
        }

        /* ── Antenna ─────────────────────── */
        .bot3d-antenna {
          position: absolute;
          bottom: 0;
          left: 50%;
          transform: translateX(-50%) rotateX(-90deg);
          width: 2px;
          height: 10px;
          background: #6366f1;
          display: flex;
          flex-direction: column;
          align-items: center;
          transform-origin: bottom center;
        }

        .bot3d-antenna-tip {
          width: 5px;
          height: 5px;
          border-radius: 50%;
          background: #06b6d4;
          box-shadow: 0 0 10px #06b6d4, 0 0 20px rgba(6, 182, 212, 0.8);
          position: absolute;
          top: -5px;
          left: -1.5px;
          animation: antennaPulse 1.8s ease-in-out infinite;
        }

        @keyframes antennaPulse {
          0%, 100% { box-shadow: 0 0 8px #06b6d4, 0 0 16px rgba(6, 182, 212, 0.7); }
          50%      { box-shadow: 0 0 14px #06b6d4, 0 0 28px rgba(6, 182, 212, 0.95); }
        }

        /* ── Neck & Body ──────────────────── */
        .bot3d-neck {
          width: 10px;
          height: 6px;
          background: rgba(59, 130, 246, 0.4);
          border: 1.5px solid rgba(59, 130, 246, 0.6);
          margin: 0 auto;
          position: relative;
          z-index: 1;
        }

        .bot3d-body {
          width: 36px;
          height: 18px;
          transform-style: preserve-3d;
          background: linear-gradient(160deg, #16264f, #231244);
          border: 1.5px solid rgba(59, 130, 246, 0.7);
          border-radius: 4px 4px 8px 8px;
          box-shadow: inset 0 0 8px rgba(59, 130, 246, 0.25), 0 4px 16px rgba(0, 0, 0, 0.5);
          margin: 0 auto;
          position: relative;
        }

        .bot3d-body::after {
          content: '';
          width: 60%;
          height: 1.5px;
          background: #06b6d4;
          box-shadow: 0 0 5px #06b6d4;
          position: absolute;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
        }

        /* ── Ground Shadow / Aura ─────────── */
        .bot3d-aura {
          width: 38px;
          height: 6px;
          background: radial-gradient(ellipse, rgba(6, 182, 212, 0.75) 0%, transparent 70%);
          filter: blur(4px);
          margin: 2px auto 0;
          animation: auraPulse 3.5s ease-in-out infinite;
        }

        @keyframes auraPulse {
          0%, 100% { transform: scaleX(1); opacity: 0.7; }
          50%      { transform: scaleX(0.75); opacity: 0.35; }
        }

        /* ── Close State ─────────────────── */
        .bot3d-close-icon {
          position: absolute;
          left: 0;
          top: 0;
          width: 58px;
          height: 58px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(15, 23, 42, 0.9);
          border: 1px solid rgba(59, 130, 246, 0.3);
          border-radius: 50%;
          box-sizing: border-box;
          opacity: 0;
          transform: scale(0.7);
          transition: all 0.2s ease;
          pointer-events: none;
          z-index: 10;
        }

        .bot3d-wrapper.is-open .bot3d-close-icon {
          opacity: 1;
          transform: scale(1);
          pointer-events: auto;
        }

        .bot3d-close-icon::before,
        .bot3d-close-icon::after {
          content: '';
          position: absolute;
          width: 2px;
          height: 20px;
          background-color: white;
          border-radius: 1px;
        }

        .bot3d-close-icon::before {
          transform: rotate(45deg);
        }

        .bot3d-close-icon::after {
          transform: rotate(-45deg);
        }

        /* ── Ping Ring Animation ─────────── */
        .bot3d-ping {
          position: absolute;
          inset: 0;
          border-radius: 50%;
          border: 1px solid rgba(59, 130, 246, 0.4);
          pointer-events: none;
          animation: bot3dPing 2.5s ease-out infinite;
        }

        @keyframes bot3dPing {
          0%   { transform: scale(1); opacity: 0.6; }
          100% { transform: scale(1.5); opacity: 0; }
        }
      `}</style>

      <div className="bot3d-container">
        <div className="bot3d-scene-wrapper">
          <div className="bot3d-scene">
            <div className="bot3d-robot">
              <div className="bot3d-head">
                <div className="face front">
                  <div className="bot3d-eye bot3d-eye-left"></div>
                  <div className="bot3d-eye bot3d-eye-right"></div>
                  <div className="bot3d-mouth">
                    <div className="bot3d-mouth-dot"></div>
                    <div className="bot3d-mouth-dot"></div>
                    <div className="bot3d-mouth-dot"></div>
                  </div>
                </div>
                <div className="face back"></div>
                <div className="face left"></div>
                <div className="face right"></div>
                <div className="face top">
                  <div className="bot3d-antenna">
                    <div className="bot3d-antenna-tip"></div>
                  </div>
                </div>
                <div className="face bottom"></div>
              </div>
              <div className="bot3d-neck"></div>
              <div className="bot3d-body"></div>
            </div>
            <div className="bot3d-aura"></div>
          </div>
        </div>

        <div className="bot3d-close-icon" onClick={(e) => {
          e.stopPropagation();
          onClick(e);
        }}></div>
      </div>

      {!isOpen && <div className="bot3d-ping"></div>}
    </div>
  );
}
