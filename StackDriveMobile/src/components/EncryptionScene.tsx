import React, { useEffect } from 'react';
import { View, StyleSheet, Dimensions } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withRepeat,
  withSequence,
  withDelay,
  Easing,
  interpolate,
} from 'react-native-reanimated';
import { colors } from '../theme/colors';

const { width, height } = Dimensions.get('window');

interface EncryptionSceneProps {
  isUnlocking?: boolean;
  isLocking?: boolean;
}

export default function EncryptionScene({ isUnlocking = false, isLocking = false }: EncryptionSceneProps) {
  // Shackle animation values
  const shackleTranslateY = useSharedValue(0);
  const shackleRotate = useSharedValue(0);

  // Keyhole rotation value
  const keyholeRotation = useSharedValue(0);

  // Background glow and scale pulse
  const pulse = useSharedValue(1);

  // Orbit rotation
  const orbit1Rotation = useSharedValue(0);
  const orbit2Rotation = useSharedValue(0);

  useEffect(() => {
    // Continuous orbit rotation
    orbit1Rotation.value = withRepeat(
      withTiming(360, { duration: 12000, easing: Easing.linear }),
      -1,
      false
    );
    orbit2Rotation.value = withRepeat(
      withTiming(-360, { duration: 16000, easing: Easing.linear }),
      -1,
      false
    );

    // Continuous glow pulse
    pulse.value = withRepeat(
      withSequence(
        withTiming(1.15, { duration: 2000, easing: Easing.inOut(Easing.ease) }),
        withTiming(0.95, { duration: 2000, easing: Easing.inOut(Easing.ease) })
      ),
      -1,
      true
    );
  }, []);

  useEffect(() => {
    if (isUnlocking) {
      // 1. Turn key first (0 -> 90deg)
      keyholeRotation.value = withTiming(90, {
        duration: 400,
        easing: Easing.inOut(Easing.ease),
      });

      // 2. Pop shackle up after key finishes turning
      shackleTranslateY.value = withDelay(400, withTiming(-25, {
        duration: 350,
        easing: Easing.out(Easing.back(1.2)),
      }));

      // 3. Swing shackle open after it pops up
      shackleRotate.value = withDelay(750, withTiming(-60, {
        duration: 500,
        easing: Easing.out(Easing.quad),
      }));

      // 4. Return keyhole to origin
      keyholeRotation.value = withDelay(1200, withTiming(0, {
        duration: 300,
      }));

      // 5. Expand background glow
      pulse.value = withDelay(400, withTiming(1.8, {
        duration: 800,
        easing: Easing.out(Easing.quad),
      }));
    } else if (isLocking) {
      // Start immediately in open state
      shackleTranslateY.value = -25;
      shackleRotate.value = -60;
      keyholeRotation.value = 0;
      pulse.value = 1.8;

      // 1. Swing shackle closed (rotate back to 0)
      shackleRotate.value = withTiming(0, {
        duration: 500,
        easing: Easing.inOut(Easing.ease),
      });

      // 2. Snap shackle down after swinging finishes (using bounce to feel physical)
      shackleTranslateY.value = withDelay(500, withTiming(0, {
        duration: 250,
        easing: Easing.out(Easing.bounce),
      }));

      // 3. Turn key briefly to lock the cylinder after snap
      keyholeRotation.value = withDelay(750, withSequence(
        withTiming(-30, { duration: 150 }),
        withTiming(0, { duration: 150 })
      ));

      // 4. Shrink back to normal glow
      pulse.value = withDelay(500, withTiming(1.0, {
        duration: 500,
        easing: Easing.inOut(Easing.ease),
      }));
    } else {
      // Reset state
      shackleTranslateY.value = withTiming(0, { duration: 300 });
      shackleRotate.value = withTiming(0, { duration: 300 });
      keyholeRotation.value = withTiming(0, { duration: 300 });
      pulse.value = withRepeat(
        withSequence(
          withTiming(1.15, { duration: 2000, easing: Easing.inOut(Easing.ease) }),
          withTiming(0.95, { duration: 2000, easing: Easing.inOut(Easing.ease) })
        ),
        -1,
        true
      );
    }
  }, [isUnlocking, isLocking]);

  // Animated styles
  const animatedShackleStyle = useAnimatedStyle(() => {
    return {
      transform: [
        { translateY: shackleTranslateY.value },
        // Rotate around left leg (origin of rotation)
        { translateX: -15 },
        { rotate: `${shackleRotate.value}deg` },
        { translateX: 15 },
      ],
    };
  });

  const animatedGlowStyle = useAnimatedStyle(() => {
    return {
      transform: [{ scale: pulse.value }],
      opacity: interpolate(pulse.value, [0.95, 1.8], [0.15, 0.45]),
    };
  });

  const animatedKeyholeStyle = useAnimatedStyle(() => {
    return {
      transform: [{ rotate: `${keyholeRotation.value}deg` }],
    };
  });

  const animatedOrbit1Style = useAnimatedStyle(() => {
    return {
      transform: [
        { rotateX: '60deg' },
        { rotateY: '15deg' },
        { rotateZ: `${orbit1Rotation.value}deg` },
      ],
    };
  });

  const animatedOrbit2Style = useAnimatedStyle(() => {
    return {
      transform: [
        { rotateX: '45deg' },
        { rotateY: '-30deg' },
        { rotateZ: `${orbit2Rotation.value}deg` },
      ],
    };
  });

  return (
    <View style={styles.container}>
      {/* Dynamic Glow Backdrops */}
      <Animated.View style={[styles.glowRing, styles.cyanGlow, animatedGlowStyle]} />
      <Animated.View style={[styles.glowRing, styles.purpleGlow, { transform: [{ scale: pulse.value * 0.8 }] }]} />

      {/* Orbit 1 */}
      <Animated.View style={[styles.orbit, styles.orbit1, animatedOrbit1Style]}>
        <View style={styles.orbitNode1} />
        <View style={styles.orbitNode2} />
      </Animated.View>

      {/* Orbit 2 */}
      <Animated.View style={[styles.orbit, styles.orbit2, animatedOrbit2Style]}>
        <View style={styles.orbitNode3} />
      </Animated.View>

      {/* Padlock Container */}
      <View style={styles.lockContainer}>
        {/* Shackle */}
        <Animated.View style={[styles.shackle, animatedShackleStyle]}>
          <View style={styles.shackleArch} />
          <View style={styles.shackleLeftLeg} />
          <View style={styles.shackleRightLeg} />
        </Animated.View>

        {/* Lock Body */}
        <View style={styles.lockBody}>
          {/* Keyhole */}
          <Animated.View style={[styles.keyholeOuter, animatedKeyholeStyle]}>
            <View style={styles.keyholeInner} />
            <View style={styles.keyholeSlit} />
          </Animated.View>
        </View>

        {/* Shield Overlay Detail */}
        <View style={styles.shieldDecoration} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    height: 240,
    width: '100%',
    alignItems: 'center',
    justifyContent: 'center',
    overflow: 'hidden',
    position: 'relative',
    marginVertical: 10,
  },
  lockContainer: {
    width: 100,
    height: 120,
    alignItems: 'center',
    justifyContent: 'flex-end',
    zIndex: 10,
  },
  shackle: {
    width: 60,
    height: 55,
    position: 'absolute',
    top: 15,
    alignItems: 'center',
    zIndex: 5,
  },
  shackleArch: {
    width: 50,
    height: 50,
    borderRadius: 25,
    borderWidth: 6,
    borderColor: colors.accent,
    borderBottomWidth: 0,
    backgroundColor: 'transparent',
  },
  shackleLeftLeg: {
    width: 6,
    height: 18,
    backgroundColor: colors.accent,
    position: 'absolute',
    bottom: -10,
    left: 5,
  },
  shackleRightLeg: {
    width: 6,
    height: 8,
    backgroundColor: colors.accent,
    position: 'absolute',
    bottom: 0,
    right: 5,
  },
  lockBody: {
    width: 90,
    height: 75,
    backgroundColor: colors.bgElevated,
    borderRadius: 16,
    borderWidth: 2,
    borderColor: colors.bgBorder,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#00e5ff',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.15,
    shadowRadius: 10,
    elevation: 5,
    zIndex: 6,
  },
  keyholeOuter: {
    width: 20,
    height: 20,
    borderRadius: 10,
    backgroundColor: colors.bgDeep,
    alignItems: 'center',
    justifyContent: 'center',
  },
  keyholeInner: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: colors.scan,
    shadowColor: colors.scan,
    shadowRadius: 4,
    shadowOpacity: 0.8,
  },
  keyholeSlit: {
    width: 4,
    height: 12,
    backgroundColor: colors.scan,
    position: 'absolute',
    bottom: 2,
  },
  shieldDecoration: {
    position: 'absolute',
    bottom: 0,
    width: 90,
    height: 15,
    borderBottomLeftRadius: 16,
    borderBottomRightRadius: 16,
    backgroundColor: 'rgba(59, 130, 246, 0.08)',
    borderTopWidth: 1,
    borderTopColor: colors.bgBorder,
    zIndex: 7,
  },
  glowRing: {
    position: 'absolute',
    width: 160,
    height: 160,
    borderRadius: 80,
    zIndex: 1,
  },
  cyanGlow: {
    backgroundColor: colors.scan,
    opacity: 0.25,
  },
  purpleGlow: {
    backgroundColor: '#7c3aed',
    opacity: 0.15,
  },
  orbit: {
    position: 'absolute',
    width: 180,
    height: 180,
    borderRadius: 90,
    borderWidth: 1,
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 2,
  },
  orbit1: {
    borderColor: 'rgba(124, 58, 237, 0.3)',
  },
  orbit2: {
    borderColor: 'rgba(0, 229, 255, 0.2)',
  },
  orbitNode1: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: '#7c3aed',
    position: 'absolute',
    top: 15,
  },
  orbitNode2: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: '#7c3aed',
    position: 'absolute',
    bottom: 15,
  },
  orbitNode3: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: colors.scan,
    position: 'absolute',
    left: 20,
    shadowColor: colors.scan,
    shadowRadius: 5,
    shadowOpacity: 0.8,
  },
});
