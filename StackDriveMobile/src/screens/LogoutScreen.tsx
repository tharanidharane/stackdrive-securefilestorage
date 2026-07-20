import React from 'react';
import { View, Text, StyleSheet, ActivityIndicator } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import EncryptionScene from '../components/EncryptionScene';

export default function LogoutScreen() {
  return (
    <View style={styles.container}>
      <StatusBar style="light" />
      
      {/* Encryption Padlock Scene in locking state */}
      <View style={styles.sceneContainer}>
        <EncryptionScene isLocking={true} />
      </View>

      {/* Overlay Status Details */}
      <View style={styles.detailsContainer}>
        <View style={styles.badge}>
          <Ionicons name="shield-checkmark" size={13} color={colors.accent} />
          <Text style={styles.badgeText}>Zero-Trust Architecture</Text>
        </View>
        
        <Text style={styles.headline}>
          Session{'\n'}
          <Text style={styles.headlineAccent}>Terminated</Text>
        </Text>
        
        <Text style={styles.description}>
          Connection successfully closed.{'\n'}
          Gateway locked.
        </Text>
      </View>

      {/* Form slide replacement card style loader */}
      <View style={styles.loaderCard}>
        <Text style={styles.loaderTitle}>Locking Gateway...</Text>
        <ActivityIndicator size="small" color={colors.accent} style={styles.spinner} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bgBase,
    justifyContent: 'space-between',
    paddingVertical: spacing['4xl'],
    alignItems: 'center',
  },
  sceneContainer: {
    width: '100%',
    height: 250,
    marginTop: spacing.xl,
    justifyContent: 'center',
    alignItems: 'center',
  },
  detailsContainer: {
    alignItems: 'center',
    paddingHorizontal: spacing.xl,
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(6, 182, 212, 0.08)',
    borderWidth: 1,
    borderColor: 'rgba(6, 182, 212, 0.2)',
    borderRadius: borderRadius.full,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    marginBottom: spacing.md,
    gap: spacing.xs,
  },
  badgeText: {
    color: colors.accent,
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    fontWeight: '600',
  },
  headline: {
    fontSize: fontSizes['2xl'],
    fontWeight: '700',
    color: colors.textPrimary,
    textAlign: 'center',
    fontFamily: 'monospace',
    lineHeight: 32,
    marginBottom: spacing.md,
  },
  headlineAccent: {
    color: colors.accent,
  },
  description: {
    fontSize: fontSizes.sm,
    color: colors.textMuted,
    textAlign: 'center',
    fontFamily: 'monospace',
    lineHeight: 20,
  },
  loaderCard: {
    backgroundColor: colors.bgSurface,
    width: '85%',
    paddingVertical: spacing.xl,
    paddingHorizontal: spacing.lg,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    alignItems: 'center',
    opacity: 0.8,
  },
  loaderTitle: {
    fontSize: fontSizes.base,
    color: colors.textPrimary,
    fontFamily: 'monospace',
    fontWeight: '600',
    marginBottom: spacing.md,
  },
  spinner: {
    marginTop: spacing.xs,
  },
});
