import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, ScrollView, RefreshControl, ActivityIndicator } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import api from '../services/api';

function SecurityStatCard({ label, value, iconName, color, suffix = '' }: any) {
  return (
    <View style={[styles.statCard, { borderLeftColor: color, borderLeftWidth: 3 }]}>
      <View style={[styles.statIconWrap, { backgroundColor: `${color}15` }]}>
        <Ionicons name={iconName} size={20} color={color} />
      </View>
      <Text style={[styles.statValue, { color }]}>
        {typeof value === 'number' ? value.toLocaleString() : value}{suffix}
      </Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );
}

const layerIcons: any = {
  'SHA-256 + VirusTotal': 'finger-print',
  'File Heuristic Analysis': 'archive',
  'ClamAV (Docker)': 'bug',
  'Sandbox (Docker)': 'cube',
};

function getRelativeTime(isoStr: string) {
  const date = new Date(isoStr);
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function SecurityScreen() {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      const data = await api.getSecurityStats();
      setStats(data);
    } catch { /* ignore */ }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <View style={styles.loadingWrap}>
        <ActivityIndicator size="large" color={colors.accent} />
      </View>
    );
  }

  const layerStats = stats?.layerStats || [];
  const threats = stats?.recentThreats || [];

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); fetchStats(); }} tintColor={colors.accent} />}
      showsVerticalScrollIndicator={false}
    >
      <Text style={styles.pageTitle}>Security Overview</Text>
      <Text style={styles.pageDesc}>Monitor your security pipeline performance and threat activity</Text>

      {/* Stats */}
      <View style={styles.statsGrid}>
        <SecurityStatCard label="Total Scanned" value={stats?.totalScanned || 0} iconName="shield-checkmark" color={colors.pass} />
        <SecurityStatCard label="Pass Rate" value={stats?.passRate || 0} iconName="trending-up" color={colors.safe} suffix="%" />
        <SecurityStatCard label="Avg Scan Time" value={stats?.avgScanTime || '—'} iconName="time" color={colors.scan} />
        <SecurityStatCard label="Active Threats" value={stats?.activeThreats || 0} iconName="warning" color={colors.threat} />
      </View>

      {/* Layer Performance */}
      {layerStats.length > 0 && (
        <>
          <Text style={styles.sectionTitle}>Layer Performance</Text>
          {layerStats.map((layer: any, i: number) => {
            const total = layer.passed + layer.failed;
            const passRate = total > 0 ? ((layer.passed / total) * 100).toFixed(1) : '0.0';
            const iconName = layerIcons[layer.name] || 'shield-checkmark';
            return (
              <View key={layer.name} style={styles.layerCard}>
                <View style={styles.layerHeader}>
                  <View style={styles.layerIconWrap}>
                    <Ionicons name={iconName} size={18} color={colors.accent} />
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.layerNum}>Layer {i + 1}</Text>
                    <Text style={styles.layerName}>{layer.name}</Text>
                  </View>
                </View>
                <View style={styles.layerBar}>
                  <View style={[styles.layerBarFill, { width: `${passRate}%` as any }]} />
                </View>
                <View style={styles.layerStats}>
                  <Text style={[styles.layerStatText, { color: colors.safe }]}>{layer.passed.toLocaleString()} passed</Text>
                  <Text style={[styles.layerStatText, { color: colors.threat }]}>{layer.failed} failed</Text>
                  <Text style={[styles.layerStatText, { color: colors.textMuted }]}>{passRate}%</Text>
                </View>
              </View>
            );
          })}
        </>
      )}

      {/* Recent Threats */}
      {threats.length > 0 && (
        <>
          <Text style={[styles.sectionTitle, { marginTop: spacing['2xl'] }]}>Recent Threat Activity</Text>
          {threats.map((threat: any) => (
            <View key={threat.id} style={styles.threatItem}>
              <View style={styles.threatIcon}>
                <Ionicons name="warning" size={16} color={colors.threat} />
              </View>
              <View style={{ flex: 1 }}>
                <View style={styles.threatHeader}>
                  <Text style={styles.threatFile} numberOfLines={1}>{threat.fileName}</Text>
                  <Text style={styles.threatTime}>{getRelativeTime(threat.detectedAt)}</Text>
                </View>
                <Text style={styles.threatDetail}>
                  <Text style={{ color: colors.threat }}>{threat.threatType}</Text> — {threat.layer}
                </Text>
                <Text style={styles.threatAction}>{threat.action}</Text>
              </View>
            </View>
          ))}
        </>
      )}

      {/* Pipeline Description */}
      <Text style={[styles.sectionTitle, { marginTop: spacing['2xl'] }]}>Security Pipeline Layers</Text>
      {[
        { num: 1, name: 'SHA-256 + VirusTotal', icon: 'finger-print', color: colors.pass,
          desc: 'Computes SHA-256 hash and queries VirusTotal threat intelligence API.' },
        { num: 2, name: 'File Heuristic Analysis', icon: 'archive', color: colors.scan,
          desc: 'ZIP bombs, path traversal, hidden files, obfuscated names, nested archives.' },
        { num: 3, name: 'ClamAV (Docker)', icon: 'bug', color: colors.queue,
          desc: 'Signature-based antivirus scan via persistent ClamAV container.' },
        { num: 4, name: 'Sandbox (Docker)', icon: 'cube', color: colors.threat,
          desc: 'Behavioral analysis in isolated ephemeral container with strace monitoring.' },
      ].map(layer => (
        <View key={layer.num} style={styles.descCard}>
          <View style={[styles.descIconWrap, { backgroundColor: `${layer.color}15` }]}>
            <Ionicons name={layer.icon as any} size={24} color={layer.color} />
          </View>
          <Text style={styles.descTitle}>Layer {layer.num} — {layer.name}</Text>
          <Text style={styles.descText}>{layer.desc}</Text>
        </View>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgBase },
  content: { padding: spacing.lg, paddingBottom: spacing['4xl'] },
  loadingWrap: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: colors.bgBase },
  pageTitle: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.sm },
  pageDesc: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, lineHeight: 22, marginBottom: spacing['2xl'] },
  statsGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.md, marginBottom: spacing['3xl'] },
  statCard: {
    width: '47%', backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.lg, borderWidth: 1, borderColor: colors.bgBorder, alignItems: 'center',
  },
  statIconWrap: { width: 40, height: 40, borderRadius: borderRadius.md, alignItems: 'center', justifyContent: 'center', marginBottom: spacing.sm },
  statValue: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '700' },
  statLabel: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xs, textAlign: 'center' },
  sectionTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.lg },
  layerCard: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.lg, marginBottom: spacing.md,
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  layerHeader: { flexDirection: 'row', alignItems: 'center', gap: spacing.md, marginBottom: spacing.md },
  layerIconWrap: {
    width: 36, height: 36, borderRadius: borderRadius.md,
    backgroundColor: colors.bgElevated, alignItems: 'center', justifyContent: 'center',
  },
  layerNum: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600', color: colors.textMuted },
  layerName: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500' },
  layerBar: {
    height: 4, backgroundColor: colors.bgElevated, borderRadius: borderRadius.full,
    overflow: 'hidden', marginBottom: spacing.sm,
  },
  layerBarFill: { height: '100%', backgroundColor: colors.safe, borderRadius: borderRadius.full },
  layerStats: { flexDirection: 'row', justifyContent: 'space-between' },
  layerStatText: { fontFamily: 'monospace', fontSize: fontSizes.xs },
  threatItem: {
    flexDirection: 'row', gap: spacing.md,
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.lg, marginBottom: spacing.sm,
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  threatIcon: {
    width: 32, height: 32, borderRadius: borderRadius.full,
    backgroundColor: colors.threatBg, alignItems: 'center', justifyContent: 'center',
  },
  threatHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  threatFile: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500', flex: 1 },
  threatTime: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  threatDetail: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textSecondary, marginTop: spacing.xs },
  threatAction: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xs },
  descCard: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.xl, marginBottom: spacing.md,
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  descIconWrap: {
    width: 48, height: 48, borderRadius: borderRadius.md,
    alignItems: 'center', justifyContent: 'center', marginBottom: spacing.md,
  },
  descTitle: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.sm },
  descText: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, lineHeight: 20 },
});
