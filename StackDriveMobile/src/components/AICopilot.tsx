import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  TextInput, ActivityIndicator, KeyboardAvoidingView, Platform,
  Modal, Dimensions, Animated, Easing,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import api from '../services/api';

const QUICK_ACTIONS = [
  { label: '🛡 What is StackDrive?', message: 'What is StackDrive and how does it protect my files?' },
  { label: '📊 My Dashboard', message: 'Give me a summary of my dashboard — how many files are safe and blocked?' },
  { label: '🏆 Compare Files', message: 'Compare my files and rank them by risk score' },
  { label: '⚠ Recent Threats', message: 'Are there any recent threats or blocked files in my account?' },
  { label: '🧭 Recommendations', message: 'What should I do next?' },
  { label: '🔐 What is ML-KEM?', message: 'What is ML-KEM and why does StackDrive use it?' },
];

const LOADING_STAGES = [
  'Looking up your files...',
  'Running analysis...',
  'Composing response...',
];

// Reusable scalable robot face avatar (perfect match for Image 2)
interface RobotAvatarProps {
  size?: number;
  glow?: boolean;
}

export function RobotAvatar({ size = 32, glow = false }: RobotAvatarProps) {
  const scale = size / 32;
  return (
    <View style={[avatarStyles.container, { width: size, height: size }]}>
      {/* Glow outer ring */}
      {glow && <View style={[avatarStyles.glowRing, { width: size * 1.2, height: size * 1.2, borderRadius: (size * 1.2) / 2 }]} />}
      
      {/* Antenna tip */}
      <View style={[avatarStyles.antennaTip, { width: 3.5 * scale, height: 3.5 * scale, borderRadius: (3.5 * scale) / 2 }]} />
      {/* Antenna line */}
      <View style={[avatarStyles.antennaLine, { height: 5 * scale, width: 1.5 * scale }]} />
      
      {/* Head */}
      <View style={[avatarStyles.head, { width: 20 * scale, height: 16 * scale, borderRadius: 3 * scale }]}>
        {/* Eyes */}
        <View style={avatarStyles.eyesRow}>
          <View style={[avatarStyles.eye, { width: 5 * scale, height: 1.5 * scale, borderRadius: 0.75 * scale }]} />
          <View style={[avatarStyles.eye, { width: 5 * scale, height: 1.5 * scale, borderRadius: 0.75 * scale }]} />
        </View>
        
        {/* Mouth dots */}
        <View style={avatarStyles.mouthRow}>
          <View style={[avatarStyles.mouthDot, { width: 1 * scale, height: 1 * scale, borderRadius: 0.5 * scale }]} />
          <View style={[avatarStyles.mouthDot, { width: 1 * scale, height: 1 * scale, borderRadius: 0.5 * scale }]} />
          <View style={[avatarStyles.mouthDot, { width: 1 * scale, height: 1 * scale, borderRadius: 0.5 * scale }]} />
        </View>
      </View>
      
      {/* Neck */}
      <View style={[avatarStyles.neck, { width: 3.5 * scale, height: 2 * scale }]} />
      
      {/* Body base */}
      <View style={[avatarStyles.base, { width: 13 * scale, height: 3.5 * scale, borderRadius: 1.5 * scale }]} />
    </View>
  );
}

const avatarStyles = StyleSheet.create({
  container: {
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
  },
  glowRing: {
    position: 'absolute',
    borderWidth: 1,
    borderColor: 'rgba(6, 182, 212, 0.3)',
    backgroundColor: 'transparent',
  },
  antennaTip: {
    backgroundColor: '#06b6d4',
  },
  antennaLine: {
    backgroundColor: '#6366f1',
  },
  head: {
    backgroundColor: '#0f162a',
    borderWidth: 1.2,
    borderColor: '#06b6d4',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 2,
    marginTop: -0.5,
  },
  eyesRow: {
    flexDirection: 'row',
    gap: 3,
    marginBottom: 1,
  },
  eye: {
    backgroundColor: '#06b6d4',
  },
  mouthRow: {
    flexDirection: 'row',
    gap: 1.5,
  },
  mouthDot: {
    backgroundColor: 'rgba(6, 182, 212, 0.7)',
  },
  neck: {
    backgroundColor: '#06b6d4',
  },
  base: {
    backgroundColor: '#0f162a',
    borderWidth: 1,
    borderColor: '#06b6d4',
  },
});

// Custom fully-animated 3D robot mockup for Native Mobile (iOS/Android)
function WelcomeMobileBot() {
  const hoverAnim = useRef(new Animated.Value(0)).current;
  const scanAnim = useRef(new Animated.Value(0)).current;
  const voice1 = useRef(new Animated.Value(1)).current;
  const voice2 = useRef(new Animated.Value(1)).current;
  const voice3 = useRef(new Animated.Value(1)).current;
  const voice4 = useRef(new Animated.Value(1)).current;
  const voice5 = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    // 1. Hover Bobbing Animation Loop
    Animated.loop(
      Animated.sequence([
        Animated.timing(hoverAnim, {
          toValue: -8,
          duration: 2500,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(hoverAnim, {
          toValue: 0,
          duration: 2500,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
      ])
    ).start();

    // 2. Scan Beam Sliding Loop
    Animated.loop(
      Animated.sequence([
        Animated.timing(scanAnim, {
          toValue: 36,
          duration: 1200,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(scanAnim, {
          toValue: 0,
          duration: 1200,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
      ])
    ).start();

    // 3. Soundwave Voice Bars Pulsing Loops
    const makePulse = (animVal: Animated.Value, delay: number, maxVal: number) => {
      return Animated.loop(
        Animated.sequence([
          Animated.delay(delay),
          Animated.timing(animVal, {
            toValue: maxVal,
            duration: 350,
            easing: Easing.inOut(Easing.ease),
            useNativeDriver: true,
          }),
          Animated.timing(animVal, {
            toValue: 0.3,
            duration: 350,
            easing: Easing.inOut(Easing.ease),
            useNativeDriver: true,
          }),
        ])
      );
    };

    makePulse(voice1, 50, 1.4).start();
    makePulse(voice2, 180, 1.5).start();
    makePulse(voice3, 300, 1.6).start();
    makePulse(voice4, 100, 1.3).start();
    makePulse(voice5, 220, 1.5).start();
  }, []);

  return (
    <View style={botStyles.wrapper}>
      {/* Ground Aura */}
      <View style={botStyles.aura} />
      
      {/* Holographic Ring */}
      <View style={botStyles.holoRing} />

      {/* Rotating / Bobbing Robot */}
      <Animated.View style={[botStyles.robot, { transform: [{ translateY: hoverAnim }] }]}>
        {/* Antennas */}
        <View style={botStyles.antennasRow}>
          <View style={botStyles.antenna}>
            <View style={botStyles.antennaTip} />
          </View>
          <View style={botStyles.antenna}>
            <View style={botStyles.antennaTip} />
          </View>
        </View>

        {/* Head Cube */}
        <View style={botStyles.head}>
          <View style={botStyles.visor}>
            <View style={botStyles.eyestrip} />
            <Animated.View style={[botStyles.scanBar, { transform: [{ translateX: scanAnim }] }]} />
          </View>
          
          <View style={botStyles.voiceBars}>
            <Animated.View style={[botStyles.voiceBar, { height: 5, transform: [{ scaleY: voice1 }] }]} />
            <Animated.View style={[botStyles.voiceBar, { height: 9, transform: [{ scaleY: voice2 }] }]} />
            <Animated.View style={[botStyles.voiceBar, { height: 13, transform: [{ scaleY: voice3 }] }]} />
            <Animated.View style={[botStyles.voiceBar, { height: 7, transform: [{ scaleY: voice4 }] }]} />
            <Animated.View style={[botStyles.voiceBar, { height: 11, transform: [{ scaleY: voice5 }] }]} />
          </View>
        </View>

        {/* Neck */}
        <View style={botStyles.neck} />

        {/* Body Cube */}
        <View style={botStyles.body}>
          <View style={botStyles.chestReactor} />
        </View>

        {/* Arms */}
        <View style={[botStyles.arm, botStyles.armLeft]} />
        <View style={[botStyles.arm, botStyles.armRight]} />

        {/* Holographic Held Screen */}
        <View style={botStyles.heldScreen}>
          <View style={botStyles.miniChat}>
            <Text style={botStyles.miniHeader}>StackDrive</Text>
            <View style={botStyles.miniBubbleLeft} />
            <View style={botStyles.miniBubbleRight} />
          </View>
          <View style={botStyles.miniInput}>
            <View style={botStyles.miniCursor} />
          </View>
        </View>

        {/* Jet Thruster Flame */}
        <View style={botStyles.thruster} />
      </Animated.View>
    </View>
  );
}

const botStyles = StyleSheet.create({
  wrapper: {
    width: 140,
    height: 140,
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
    marginVertical: spacing.md,
  },
  robot: {
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
    width: 100,
    height: 100,
  },
  antennasRow: {
    flexDirection: 'row',
    gap: 16,
    marginBottom: -2,
    zIndex: 2,
  },
  antenna: {
    width: 2,
    height: 12,
    backgroundColor: '#6366f1',
    position: 'relative',
  },
  antennaTip: {
    width: 4,
    height: 4,
    borderRadius: 2,
    backgroundColor: '#06b6d4',
    position: 'absolute',
    top: -4,
    left: -1,
    shadowColor: '#06b6d4',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.8,
    shadowRadius: 4,
  },
  head: {
    width: 60,
    height: 50,
    backgroundColor: '#0f172a',
    borderWidth: 1.5,
    borderColor: '#3b82f6',
    borderRadius: 4,
    alignItems: 'center',
    paddingTop: 8,
    zIndex: 3,
  },
  visor: {
    width: 48,
    height: 16,
    backgroundColor: 'rgba(6, 182, 212, 0.12)',
    borderWidth: 1,
    borderColor: 'rgba(6, 182, 212, 0.35)',
    borderRadius: 3,
    position: 'relative',
    overflow: 'hidden',
  },
  eyestrip: {
    width: 38,
    height: 2,
    backgroundColor: '#06b6d4',
    borderRadius: 1,
    position: 'absolute',
    top: 6,
    left: 4,
  },
  scanBar: {
    width: 6,
    height: '100%',
    backgroundColor: 'rgba(255, 255, 255, 0.8)',
    position: 'absolute',
    top: 0,
    left: 0,
  },
  voiceBars: {
    flexDirection: 'row',
    gap: 2,
    position: 'absolute',
    bottom: 6,
  },
  voiceBar: {
    width: 2,
    backgroundColor: '#06b6d4',
    borderRadius: 1,
  },
  neck: {
    width: 12,
    height: 8,
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: 'rgba(59, 130, 246, 0.25)',
    marginTop: -2,
    zIndex: 2,
  },
  body: {
    width: 48,
    height: 30,
    backgroundColor: '#0d1535',
    borderWidth: 1.5,
    borderColor: '#3b82f6',
    borderRadius: 4,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: -2,
    zIndex: 3,
  },
  chestReactor: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: '#06b6d4',
    shadowColor: '#06b6d4',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.8,
    shadowRadius: 5,
  },
  arm: {
    width: 8,
    height: 16,
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: 'rgba(59, 130, 246, 0.3)',
    borderRadius: 2,
    position: 'absolute',
    top: 62,
    zIndex: 2,
  },
  armLeft: {
    left: 14,
  },
  armRight: {
    right: 14,
  },
  heldScreen: {
    position: 'absolute',
    bottom: 4,
    width: 54,
    height: 38,
    backgroundColor: 'rgba(6, 182, 212, 0.15)',
    borderWidth: 1.5,
    borderColor: 'rgba(6, 182, 212, 0.6)',
    borderRadius: 4,
    padding: 3,
    justifyContent: 'space-between',
    zIndex: 4,
  },
  miniChat: {
    gap: 2,
  },
  miniHeader: {
    fontSize: 5,
    fontWeight: '700',
    color: '#06b6d4',
    textAlign: 'center',
  },
  miniBubbleLeft: {
    width: 26,
    height: 2,
    backgroundColor: 'rgba(255, 255, 255, 0.6)',
    borderRadius: 1,
  },
  miniBubbleRight: {
    width: 18,
    height: 2,
    backgroundColor: 'rgba(6, 182, 212, 0.75)',
    borderRadius: 1,
    alignSelf: 'flex-end',
  },
  miniInput: {
    height: 4,
    backgroundColor: 'rgba(255, 255, 255, 0.15)',
    borderWidth: 0.5,
    borderColor: 'rgba(6, 182, 212, 0.4)',
    borderRadius: 1,
    justifyContent: 'center',
    paddingLeft: 2,
  },
  miniCursor: {
    width: 1.5,
    height: 2,
    backgroundColor: '#06b6d4',
  },
  thruster: {
    width: 16,
    height: 8,
    backgroundColor: '#3b82f6',
    borderBottomLeftRadius: 8,
    borderBottomRightRadius: 8,
    position: 'absolute',
    bottom: 4,
    opacity: 0.5,
    zIndex: 1,
  },
  holoRing: {
    position: 'absolute',
    width: 110,
    height: 30,
    borderWidth: 1.5,
    borderColor: 'rgba(6, 182, 212, 0.4)',
    borderRadius: 55,
    transform: [{ rotateX: '75deg' }],
    bottom: 22,
    borderStyle: 'dashed',
    zIndex: 1,
  },
  aura: {
    position: 'absolute',
    bottom: 10,
    width: 80,
    height: 16,
    backgroundColor: 'rgba(59, 130, 246, 0.2)',
    borderRadius: 40,
  },
});

// Dynamic Platform-Specific WelcomeBot3D for Web (dangerouslySetInnerHTML based)
function WelcomeWebBot() {
  const div = (props: any, ...children: any[]) => React.createElement('div', props, ...children);
  const style = (props: any, content: string) => React.createElement('style', { ...props, dangerouslySetInnerHTML: { __html: content } });

  return div({ className: 'welcome3d-wrapper' },
    style({}, `
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
        0% { transform: scale(0.78) rotateY(0deg) rotateX(-12deg) translateY(0px); }
        50% { transform: scale(0.78) rotateY(180deg) rotateX(-12deg) translateY(-8px); }
        100% { transform: scale(0.78) rotateY(360deg) rotateX(-12deg) translateY(0px); }
      }
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
    `),
    div({ className: 'welcome3d-scene' },
      div({ className: 'welcome3d-robot' },
        // Head Cube
        div({ className: 'welcome3d-head' },
          div({ className: 'face front' },
            div({ className: 'welcome3d-visor' },
              div({ className: 'welcome3d-eyestrip' }),
              div({ className: 'welcome3d-scan-bar' })
            ),
            div({ className: 'welcome3d-voice-bars' },
              div({ className: 'voice-bar bar-1' }),
              div({ className: 'voice-bar bar-2' }),
              div({ className: 'voice-bar bar-3' }),
              div({ className: 'voice-bar bar-4' }),
              div({ className: 'voice-bar bar-5' })
            )
          ),
          div({ className: 'face back' },
            div({ className: 'welcome3d-reactor-outer' },
              div({ className: 'welcome3d-reactor-inner' })
            )
          ),
          div({ className: 'face left' },
            div({ className: 'welcome3d-vents' },
              div({ className: 'welcome3d-vent-line' }),
              div({ className: 'welcome3d-vent-line' }),
              div({ className: 'welcome3d-vent-line' })
            )
          ),
          div({ className: 'face right' },
            div({ className: 'welcome3d-vents' },
              div({ className: 'welcome3d-vent-line' }),
              div({ className: 'welcome3d-vent-line' }),
              div({ className: 'welcome3d-vent-line' })
            )
          ),
          div({ className: 'face top' },
            div({ className: 'welcome3d-twin-antennas' },
              div({ className: 'welcome-antenna ant-left' }, div({ className: 'tip' })),
              div({ className: 'welcome-antenna ant-right' }, div({ className: 'tip' }))
            )
          ),
          div({ className: 'face bottom' })
        ),
        // Neck Cube
        div({ className: 'welcome3d-neck' },
          div({ className: 'face front' }),
          div({ className: 'face back' }),
          div({ className: 'face left' }),
          div({ className: 'face right' }),
          div({ className: 'face top' }),
          div({ className: 'face bottom' })
        ),
        // Body Cube
        div({ className: 'welcome3d-body' },
          div({ className: 'face front' },
            div({ className: 'welcome3d-chest-reactor' })
          ),
          div({ className: 'face back' }),
          div({ className: 'face left' },
            div({ className: 'welcome3d-vents' },
              div({ className: 'welcome3d-vent-line' }),
              div({ className: 'welcome3d-vent-line' })
            )
          ),
          div({ className: 'face right' },
            div({ className: 'welcome3d-vents' },
              div({ className: 'welcome3d-vent-line' }),
              div({ className: 'welcome3d-vent-line' })
            )
          ),
          div({ className: 'face top' }),
          div({ className: 'face bottom' },
            div({ className: 'welcome3d-thruster' })
          )
        ),
        // Left Arm
        div({ className: 'welcome3d-arm welcome3d-arm-left' },
          div({ className: 'face front' }),
          div({ className: 'face back' }),
          div({ className: 'face left' }),
          div({ className: 'face right' }),
          div({ className: 'face top' }),
          div({ className: 'face bottom' })
        ),
        // Right Arm
        div({ className: 'welcome3d-arm welcome3d-arm-right' },
          div({ className: 'face front' }),
          div({ className: 'face back' }),
          div({ className: 'face left' }),
          div({ className: 'face right' }),
          div({ className: 'face top' }),
          div({ className: 'face bottom' })
        ),
        // Held Holographic Screen
        div({ className: 'welcome3d-held-screen' },
          div({ className: 'welcome3d-mini-chat' },
            div({ className: 'welcome3d-mini-header' }, 'StackDrive'),
            div({ className: 'welcome3d-mini-bubble-left' }),
            div({ className: 'welcome3d-mini-bubble-right' })
          ),
          div({ className: 'welcome3d-mini-input' },
            div({ className: 'welcome3d-mini-cursor' })
          )
        ),
        // Holographic Ring
        div({ className: 'welcome3d-ring' })
      ),
      div({ className: 'welcome3d-aura' })
    )
  );
}

// Final WelcomeBot Component loader
function WelcomeBot() {
  if (Platform.OS === 'web') {
    return <WelcomeWebBot />;
  }
  return <WelcomeMobileBot />;
}

interface AICopilotProps {
  visible: boolean;
  onClose: () => void;
}

export default function AICopilot({ visible, onClose }: AICopilotProps) {
  const [messages, setMessages] = useState<any[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [files, setFiles] = useState<any[]>([]);
  const [selectedFileId, setSelectedFileId] = useState('');
  const [loadingMsg, setLoadingMsg] = useState(LOADING_STAGES[0]);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const { addToast } = useToast();

  useEffect(() => {
    if (!dropdownOpen) {
      setSearchQuery('');
    }
  }, [dropdownOpen]);
  
  const scrollViewRef = useRef<ScrollView>(null);
  const loadingIntervalRef = useRef<any>(null);

  // Fetch files when component becomes visible
  useEffect(() => {
    if (visible) {
      api.getFiles('all')
        .then((data: any) => {
          if (data.files) {
            const uniqueFiles: any[] = [];
            const seenNames = new Set();
            for (const f of data.files) {
              if (!seenNames.has(f.name)) {
                seenNames.add(f.name);
                uniqueFiles.push(f);
              }
            }
            setFiles(uniqueFiles);
          }
        })
        .catch(err => console.error(err));
    }
  }, [visible]);

  // Cycle loading messages when loading
  useEffect(() => {
    if (isLoading) {
      let stage = 0;
      setLoadingMsg(LOADING_STAGES[0]);
      loadingIntervalRef.current = setInterval(() => {
        stage = Math.min(stage + 1, LOADING_STAGES.length - 1);
        setLoadingMsg(LOADING_STAGES[stage]);
      }, 2000);
    } else {
      if (loadingIntervalRef.current) clearInterval(loadingIntervalRef.current);
    }
    return () => {
      if (loadingIntervalRef.current) clearInterval(loadingIntervalRef.current);
    };
  }, [isLoading]);

  const sendMessage = async (text: string) => {
    const userMessage = text.trim();
    if (!userMessage || isLoading) return;

    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setInput('');
    setIsLoading(true);

    try {
      const data = await api.sendCopilotMessage(userMessage, selectedFileId || null);
      setMessages(prev => [...prev, {
        role: 'bot',
        content: data.reply || "I couldn't process that request. Please try again.",
      }]);
    } catch (err: any) {
      setMessages(prev => [...prev, {
        role: 'bot',
        content: `⚠ ${err.message || 'Connection error. Please check that the backend is running.'}`,
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSend = () => sendMessage(input);

  const handleNewChat = async () => {
    setMessages([]);
    try {
      await api.clearCopilotHistory();
      addToast('Conversation history reset', 'success');
    } catch (err) {
      console.warn('Failed to clear history:', err);
    }
  };

  const handleCopyMessage = async (text: string, idx: number) => {
    try {
      await Clipboard.setStringAsync(text);
      setCopiedIdx(idx);
      addToast('Message copied to clipboard', 'success');
      setTimeout(() => setCopiedIdx(null), 2000);
    } catch (e) {
      console.warn('Failed to copy text', e);
    }
  };

  const getFileStatusEmoji = (status: string) => {
    if (status === 'safe') return '✅';
    if (status === 'blocked') return '🚫';
    if (status === 'scanning') return '🔄';
    return '⏳';
  };

  // Bot message markdown-like parser (matches web formatMessage exactly)
  function parseMessageText(text: string) {
    if (!text) return null;

    const lines = text.split('\n');

    return lines.map((line, lineIndex) => {
      // Heading detection
      if (line.startsWith('### ')) {
        return (
          <Text key={lineIndex} style={styles.msgH4}>
            {processInline(line.slice(4))}
          </Text>
        );
      }
      if (line.startsWith('## ')) {
        return (
          <Text key={lineIndex} style={styles.msgH3}>
            {processInline(line.slice(3))}
          </Text>
        );
      }
      if (line.startsWith('# ')) {
        return (
          <Text key={lineIndex} style={styles.msgH2}>
            {processInline(line.slice(2))}
          </Text>
        );
      }
      if (line.trim() === '---') {
        return <View key={lineIndex} style={styles.msgHr} />;
      }

      const parts = processInline(line);

      return (
        <Text key={lineIndex} style={styles.inlineText}>
          {parts}
          {lineIndex < lines.length - 1 ? '\n' : ''}
        </Text>
      );
    });
  }

  function processInline(line: string) {
    const parts: React.ReactNode[] = [];
    let remaining = line;
    let key = 0;

    while (remaining.length > 0) {
      const boldMatch = remaining.match(/\*\*(.+?)\*\*/);
      const codeMatch = remaining.match(/`([^`]+)`/);

      let earliestMatch = null;
      let earliestIndex = remaining.length;
      let matchType = null;

      if (boldMatch && boldMatch.index !== undefined && boldMatch.index < earliestIndex) {
        earliestMatch = boldMatch;
        earliestIndex = boldMatch.index;
        matchType = 'bold';
      }
      if (codeMatch && codeMatch.index !== undefined && codeMatch.index < earliestIndex) {
        earliestMatch = codeMatch;
        earliestIndex = codeMatch.index;
        matchType = 'code';
      }

      if (!earliestMatch) {
        parts.push(<Text key={key++}>{remaining}</Text>);
        break;
      }

      if (earliestIndex > 0) {
        parts.push(<Text key={key++}>{remaining.substring(0, earliestIndex)}</Text>);
      }

      if (matchType === 'bold') {
        parts.push(
          <Text key={key++} style={styles.msgBold}>
            {earliestMatch[1]}
          </Text>
        );
      } else if (matchType === 'code') {
        parts.push(
          <Text key={key++} style={styles.msgCode}>
            {earliestMatch[1]}
          </Text>
        );
      }

      remaining = remaining.substring(earliestIndex + earliestMatch[0].length);
    }

    return parts;
  }

  const selectedFile = files.find(f => f.id === selectedFileId);

  return (
    <Modal
      visible={visible}
      animationType="slide"
      transparent={true}
      onRequestClose={onClose}
    >
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.modalOverlay}
      >
        <View style={styles.container}>
          {/* Header */}
          <View style={styles.header}>
            <View style={styles.headerLeft}>
              <RobotAvatar size={32} />
              <View>
                <Text style={styles.headerTitle}>StackDrive Bot</Text>
                <View style={styles.statusRow}>
                  <View style={styles.statusDot} />
                  <Text style={styles.statusText}>AI-Powered</Text>
                </View>
              </View>
            </View>
            <View style={styles.headerRight}>
              <TouchableOpacity style={styles.headerAction} onPress={handleNewChat}>
                <Ionicons name="refresh-outline" size={20} color={colors.textSecondary} />
              </TouchableOpacity>
              <TouchableOpacity style={styles.headerAction} onPress={() => setMessages([])}>
                <Ionicons name="trash-outline" size={20} color={colors.textSecondary} />
              </TouchableOpacity>
              <TouchableOpacity style={styles.closeBtn} onPress={onClose}>
                <Ionicons name="close" size={24} color={colors.textSecondary} />
              </TouchableOpacity>
            </View>
          </View>

          {/* Messages list */}
          <ScrollView
            ref={scrollViewRef}
            contentContainerStyle={styles.scrollContent}
            onContentSizeChange={() => scrollViewRef.current?.scrollToEnd({ animated: true })}
          >
            {messages.length === 0 ? (
              <View style={styles.welcomeContainer}>
                {/* Robot illustration - dynamically handles web 3D model & native mobile mockup */}
                <WelcomeBot />
                
                <Text style={styles.welcomeTitle}>StackDrive Bot</Text>
                <Text style={styles.welcomeSubtitle}>
                  I can explain scan results, tell you why files were blocked,
                  generate security reports, compare threats, and answer cybersecurity questions.
                </Text>

                {/* Quick actions in wrap */}
                <View style={styles.quickActionsContainer}>
                  {QUICK_ACTIONS.map((action, i) => (
                    <TouchableOpacity
                      key={i}
                      style={styles.quickBtn}
                      onPress={() => sendMessage(action.message)}
                    >
                      <Text style={styles.quickBtnText}>{action.label}</Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>
            ) : (
              messages.map((msg, i) => {
                const isBot = msg.role === 'bot';
                return (
                  <View key={i} style={[styles.msgRow, isBot ? styles.msgRowBot : styles.msgRowUser]}>
                    <View style={[styles.avatar, isBot ? styles.avatarBot : styles.avatarUser]}>
                      {isBot ? (
                        <RobotAvatar size={24} />
                      ) : (
                        <Ionicons name="person" size={12} color="#fff" />
                      )}
                    </View>
                    <View style={styles.msgBubbleWrap}>
                      <View style={[styles.bubble, isBot ? styles.bubbleBot : styles.bubbleUser]}>
                        {isBot ? (
                          <View style={styles.formattedTextContainer}>
                            {parseMessageText(msg.content)}
                          </View>
                        ) : (
                          <Text style={styles.msgTextUser}>
                            {msg.content}
                          </Text>
                        )}
                      </View>
                      
                      {isBot && (
                        <TouchableOpacity
                          style={styles.copyBtn}
                          onPress={() => handleCopyMessage(msg.content, i)}
                          activeOpacity={0.7}
                        >
                          <Ionicons
                            name={copiedIdx === i ? "checkmark" : "copy-outline"}
                            size={12}
                            color={copiedIdx === i ? colors.safe : colors.textSecondary}
                          />
                          <Text style={[styles.copyBtnText, copiedIdx === i && styles.copyBtnTextActive]}>
                            {copiedIdx === i ? 'Copied' : 'Copy'}
                          </Text>
                        </TouchableOpacity>
                      )}
                    </View>
                  </View>
                );
              })
            )}

            {isLoading && (
              <View style={[styles.msgRow, styles.msgRowBot]}>
                <View style={[styles.avatar, styles.avatarBot]}>
                  <RobotAvatar size={24} />
                </View>
                <View style={styles.msgBubbleWrap}>
                  <View style={[styles.bubble, styles.bubbleBot, styles.bubbleTyping]}>
                    <ActivityIndicator size="small" color={colors.accent} style={styles.typingIndicator} />
                    <Text style={styles.typingText}>{loadingMsg}</Text>
                  </View>
                </View>
              </View>
            )}
          </ScrollView>

          {/* Input Area */}
          <View style={styles.inputArea}>
            {files.length > 0 && (
              <View style={styles.dropdownContainer}>
                <TouchableOpacity
                  style={styles.dropdownTrigger}
                  onPress={() => setDropdownOpen(!dropdownOpen)}
                  activeOpacity={0.8}
                >
                  <Text style={styles.dropdownTriggerText} numberOfLines={1}>
                    {selectedFile ? `${getFileStatusEmoji(selectedFile.status)} ${selectedFile.name}` : 'Select a file for quick actions...'}
                  </Text>
                  <Ionicons name={dropdownOpen ? "chevron-up" : "chevron-down"} size={16} color={colors.textSecondary} />
                </TouchableOpacity>

                {dropdownOpen && (
                  <View style={styles.dropdownList}>
                    <View style={styles.dropdownSearchContainer}>
                      <Ionicons name="search" size={14} color={colors.textSecondary} style={{ marginRight: 6 }} />
                      <TextInput
                        style={styles.dropdownSearchInput}
                        value={searchQuery}
                        onChangeText={setSearchQuery}
                        placeholder="Search files..."
                        placeholderTextColor={colors.textMuted}
                        autoCapitalize="none"
                        autoCorrect={false}
                      />
                      {searchQuery ? (
                        <TouchableOpacity onPress={() => setSearchQuery('')} style={{ padding: 4 }}>
                          <Ionicons name="close-circle" size={16} color={colors.textSecondary} />
                        </TouchableOpacity>
                      ) : null}
                    </View>
                    <ScrollView style={{ maxHeight: 260 }} keyboardShouldPersistTaps="handled">
                      <TouchableOpacity
                        style={[styles.dropdownItem, !selectedFileId && styles.dropdownItemActive]}
                        onPress={() => {
                          setSelectedFileId('');
                          setDropdownOpen(false);
                        }}
                      >
                        <Text style={[styles.dropdownItemText, !selectedFileId && styles.dropdownItemTextActive]}>
                          None (Clear file context)
                        </Text>
                      </TouchableOpacity>
                      {files
                        .filter((f) => f.name.toLowerCase().includes(searchQuery.toLowerCase()))
                        .map((f) => {
                          const isActive = selectedFileId === f.id;
                          return (
                            <TouchableOpacity
                              key={f.id}
                              style={[styles.dropdownItem, isActive && styles.dropdownItemActive]}
                              onPress={() => {
                                setSelectedFileId(f.id);
                                setDropdownOpen(false);
                              }}
                            >
                              <Text style={[styles.dropdownItemText, isActive && styles.dropdownItemTextActive]}>
                                {getFileStatusEmoji(f.status)} {f.name}
                              </Text>
                            </TouchableOpacity>
                          );
                        })}
                    </ScrollView>
                  </View>
                )}
              </View>
            )}

            {selectedFileId && (
              <View style={styles.quickFileActions}>
                <TouchableOpacity
                  style={styles.fileActionBtn}
                  onPress={() => sendMessage(`Explain what ${files.find(f => f.id === selectedFileId)?.name} is`)}
                >
                  <Text style={styles.fileActionText}>🔍 Explain</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={styles.fileActionBtn}
                  onPress={() => sendMessage(`Why was ${files.find(f => f.id === selectedFileId)?.name} detected?`)}
                >
                  <Text style={styles.fileActionText}>🚫 Why Blocked?</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={styles.fileActionBtn}
                  onPress={() => sendMessage(`How dangerous is ${files.find(f => f.id === selectedFileId)?.name}?`)}
                >
                  <Text style={styles.fileActionText}>⚠ Risk Level</Text>
                </TouchableOpacity>
              </View>
            )}

            <View style={styles.inputRow}>
              <TextInput
                value={input}
                onChangeText={setInput}
                placeholder="Ask about your files, threats, or security..."
                placeholderTextColor={colors.textMuted}
                style={[styles.input, { maxHeight: 100 }]}
                multiline
                editable={!isLoading}
              />
              <TouchableOpacity
                style={[styles.sendBtn, !input.trim() && styles.sendBtnDisabled]}
                onPress={handleSend}
                disabled={!input.trim() || isLoading}
              >
                <Ionicons name="send" size={16} color="#fff" />
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    justifyContent: 'flex-end',
  },
  container: {
    height: '85%',
    backgroundColor: colors.bgBase,
    borderTopLeftRadius: borderRadius.xl,
    borderTopRightRadius: borderRadius.xl,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    overflow: 'hidden',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    borderBottomWidth: 1,
    borderBottomColor: colors.bgBorder,
    backgroundColor: colors.bgSurface,
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  headerTitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.base,
    fontWeight: '700',
    color: colors.textPrimary,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    marginTop: 2,
  },
  statusDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: colors.safe,
  },
  statusText: {
    fontFamily: 'monospace',
    fontSize: 10,
    color: '#06b6d4',
    fontWeight: '600',
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  headerAction: {
    padding: spacing.xs,
  },
  closeBtn: {
    padding: spacing.xs,
    marginLeft: spacing.xs,
  },
  scrollContent: {
    padding: spacing.lg,
    flexGrow: 1,
  },
  welcomeContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: spacing.lg,
  },
  welcomeTitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xl,
    fontWeight: '700',
    color: colors.textPrimary,
    marginBottom: spacing.xs,
    textAlign: 'center',
  },
  welcomeSubtitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textSecondary,
    textAlign: 'center',
    lineHeight: 20,
    paddingHorizontal: spacing.sm,
    marginBottom: spacing.xl,
  },
  quickActionsContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
    justifyContent: 'center',
    paddingHorizontal: spacing.xs,
  },
  quickBtn: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderRadius: borderRadius.full,
    backgroundColor: 'rgba(30, 41, 59, 0.4)',
    borderWidth: 1,
    borderColor: 'rgba(71, 85, 105, 0.3)',
  },
  quickBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
  },
  msgRow: {
    flexDirection: 'row',
    marginBottom: spacing.lg,
    gap: spacing.sm,
    maxWidth: '85%',
  },
  msgRowBot: {
    alignSelf: 'flex-start',
  },
  msgRowUser: {
    alignSelf: 'flex-end',
    flexDirection: 'row-reverse',
  },
  avatar: {
    width: 28,
    height: 28,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 4,
  },
  avatarBot: {
    backgroundColor: 'transparent',
  },
  avatarUser: {
    backgroundColor: colors.accent,
  },
  msgBubbleWrap: {
    flex: 1,
    gap: 4,
  },
  bubble: {
    borderRadius: borderRadius.md,
    padding: spacing.md,
    borderWidth: 1,
  },
  bubbleBot: {
    backgroundColor: colors.bgSurface,
    borderColor: colors.bgBorder,
  },
  bubbleUser: {
    backgroundColor: colors.accent,
    borderColor: colors.accent,
  },
  bubbleTyping: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  msgText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    lineHeight: 20,
  },
  msgTextBot: {
    color: colors.textPrimary,
  },
  msgTextUser: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    lineHeight: 20,
    color: '#fff',
  },
  formattedTextContainer: {
    gap: 4,
  },
  msgH2: {
    fontFamily: 'monospace',
    fontSize: fontSizes.lg,
    fontWeight: '700',
    color: colors.textPrimary,
    marginVertical: spacing.xs,
  },
  msgH3: {
    fontFamily: 'monospace',
    fontSize: fontSizes.base,
    fontWeight: '700',
    color: colors.textPrimary,
    marginVertical: spacing.xs,
  },
  msgH4: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    fontWeight: '600',
    color: colors.textPrimary,
    marginVertical: spacing.xs,
  },
  msgHr: {
    height: 1,
    backgroundColor: colors.bgBorder,
    marginVertical: spacing.xs,
  },
  inlineText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textPrimary,
    lineHeight: 20,
  },
  msgBold: {
    fontWeight: '700',
    color: colors.white,
  },
  msgCode: {
    fontFamily: 'monospace',
    color: colors.brandGreen,
    backgroundColor: 'rgba(74, 222, 128, 0.1)',
    paddingHorizontal: 4,
    borderRadius: borderRadius.sm,
  },
  copyBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingVertical: 2,
    paddingHorizontal: spacing.xs,
    alignSelf: 'flex-start',
  },
  copyBtnText: {
    fontFamily: 'monospace',
    fontSize: 10,
    color: colors.textSecondary,
  },
  copyBtnTextActive: {
    color: colors.safe,
  },
  typingIndicator: {
    marginRight: spacing.xs,
  },
  typingText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
  },
  inputArea: {
    padding: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.bgBorder,
    backgroundColor: colors.bgSurface,
  },
  dropdownContainer: {
    position: 'relative',
    marginBottom: spacing.sm,
    zIndex: 10,
  },
  dropdownTrigger: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    backgroundColor: '#090d16',
    borderWidth: 1,
    borderColor: 'rgba(71, 85, 105, 0.4)',
    borderRadius: borderRadius.md,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
  },
  dropdownTriggerText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textPrimary,
    flex: 1,
    marginRight: spacing.sm,
  },
  dropdownList: {
    backgroundColor: '#090d16',
    borderWidth: 1,
    borderColor: 'rgba(71, 85, 105, 0.4)',
    borderRadius: borderRadius.md,
    marginTop: spacing.xs,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 5,
  },
  dropdownSearchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.md,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(71, 85, 105, 0.2)',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
  },
  dropdownSearchInput: {
    flex: 1,
    height: 38,
    color: colors.textPrimary,
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    padding: 0,
  },
  dropdownItem: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(71, 85, 105, 0.1)',
  },
  dropdownItemActive: {
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
  },
  dropdownItemText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
  },
  dropdownItemTextActive: {
    color: colors.accent,
    fontWeight: '600',
  },
  quickFileActions: {
    flexDirection: 'row',
    gap: spacing.sm,
    marginBottom: spacing.sm,
  },
  fileActionBtn: {
    flex: 1,
    paddingVertical: spacing.xs,
    alignItems: 'center',
    borderRadius: borderRadius.sm,
    backgroundColor: colors.bgBase,
    borderWidth: 1,
    borderColor: colors.bgBorder,
  },
  fileActionText: {
    fontFamily: 'monospace',
    fontSize: 11,
    color: colors.textSecondary,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  input: {
    flex: 1,
    backgroundColor: '#090d16',
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: 'rgba(71, 85, 105, 0.4)',
    paddingHorizontal: spacing.md,
    paddingVertical: Platform.OS === 'ios' ? spacing.md : spacing.sm,
    color: colors.textPrimary,
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
  },
  sendBtn: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: '#2563eb',
    alignItems: 'center',
    justifyContent: 'center',
  },
  sendBtnDisabled: {
    opacity: 0.6,
  },
});
