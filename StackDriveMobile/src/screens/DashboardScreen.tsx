import React, { useState, useEffect, useCallback } from 'react';
import { View, Text, StyleSheet, ScrollView, RefreshControl, TouchableOpacity, ActivityIndicator } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

function StatCard({ label, value, sublabel, iconName, status }: any) {
  const statusColors: any = {
    safe: colors.safe, threat: colors.threat, scan: colors.scan, queue: colors.queue,
  };
  const color = statusColors[status] || colors.textPrimary;

  return (
    <View style={[styles.statCard, { borderTopColor: color }]}>
      <View style={styles.statHeader}>
        <Text style={styles.statLabel}>{label}</Text>
        <View style={[styles.statIconWrap, { backgroundColor: `${color}15` }]}>
          <Ionicons name={iconName} size={20} color={color} />
        </View>
      </View>
      <Text style={[styles.statValue, { color }]}>{typeof value === 'number' ? value.toLocaleString() : value}</Text>
      {sublabel ? <Text style={styles.statSublabel}>{sublabel}</Text> : null}
    </View>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config: any = {
    safe: { label: 'SAFE', bg: colors.badgeSafe, color: colors.safe },
    blocked: { label: 'BLOCKED', bg: colors.badgeThreat, color: colors.threat },
    scanning: { label: 'SCANNING', bg: colors.badgeScan, color: colors.scan },
    quarantine: { label: 'QUARANTINE', bg: colors.badgeQueue, color: colors.queue },
  };
  const c = config[status] || { label: status?.toUpperCase(), bg: colors.bgElevated, color: colors.textMuted };
  return (
    <View style={[styles.badge, { backgroundColor: `${c.color}20` }]}>
      <Text style={[styles.badgeText, { color: c.color }]}>{c.label}</Text>
    </View>
  );
}

function getRelativeTime(dateInput: string | Date) {
  const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function DashboardScreen({ navigation }: any) {
  const [files, setFiles] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const { addToast } = useToast();
  const { user } = useAuth();

  const fetchData = useCallback(async () => {
    try {
      const [metricsData, filesData] = await Promise.all([
        api.getDashboardMetrics(),
        api.getFiles(),
      ]);
      setMetrics(metricsData);
      setFiles(filesData.files || []);
    } catch (err: any) {
      if (err.status !== 401) addToast('Failed to load dashboard', 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  if (loading && !metrics) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color={colors.accent} />
      </View>
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.accent} />}
      showsVerticalScrollIndicator={false}
    >
      {/* Welcome header */}
      <View style={styles.welcomeRow}>
        <View>
          <Text style={styles.welcomeText}>Welcome back</Text>
          <Text style={styles.emailText}>{user?.email || 'User'}</Text>
        </View>
        <View style={[styles.statusDot, { backgroundColor: user?.aws_connected ? colors.safe : colors.queue }]} />
      </View>

      {/* Metrics */}
      <View style={styles.metricsGrid}>
        <StatCard
          label={metrics?.filesSafe?.label || 'Files Safe'}
          value={metrics?.filesSafe?.value ?? 0}
          sublabel={metrics?.filesSafe?.sublabel || ''}
          iconName="shield-checkmark"
          status="safe"
        />
        <StatCard
          label={metrics?.threatsBlocked?.label || 'Threats Blocked'}
          value={metrics?.threatsBlocked?.value ?? 0}
          sublabel={metrics?.threatsBlocked?.sublabel || ''}
          iconName="shield-half"
          status="threat"
        />
        <StatCard
          label={metrics?.scanningNow?.label || 'Scanning Now'}
          value={metrics?.scanningNow?.value ?? 0}
          sublabel={metrics?.scanningNow?.sublabel || ''}
          iconName="scan"
          status="scan"
        />
        <StatCard
          label={metrics?.inQuarantine?.label || 'In Quarantine'}
          value={metrics?.inQuarantine?.value ?? 0}
          sublabel={metrics?.inQuarantine?.sublabel || ''}
          iconName="time"
          status="queue"
        />
      </View>

      {/* Recent Files */}
      <Text style={styles.sectionTitle}>Recent Files</Text>
      {files.length === 0 ? (
        <View style={styles.emptyState}>
          <Ionicons name="folder-open-outline" size={48} color={colors.textMuted} />
          <Text style={styles.emptyTitle}>No files uploaded yet</Text>
          <Text style={styles.emptyText}>Upload a file to get started</Text>
        </View>
      ) : (
        files.slice(0, 7).map((file: any) => (
          <TouchableOpacity
            key={file.id}
            style={[styles.fileRow, file.status === 'blocked' && styles.fileRowBlocked]}
            activeOpacity={0.7}
            onPress={() => navigation?.navigate?.('FileDetail', { file })}
          >
            <View style={styles.fileMain}>
              <Text style={styles.fileName} numberOfLines={1}>{file.name}</Text>
              <Text style={styles.fileMeta}>
                {file.size} {file.sizeUnit || 'MB'} · {getRelativeTime(file.uploadedAt)}
              </Text>
            </View>
            <View style={styles.fileRight}>
              <StatusBadge status={file.status} />
              {file.risk !== null && file.risk !== undefined && (
                <Text style={[
                  styles.riskText,
                  { color: file.risk < 10 ? colors.safe : file.risk <= 60 ? colors.queue : colors.threat }
                ]}>
                  {file.risk}%
                </Text>
              )}
            </View>
          </TouchableOpacity>
        ))
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgBase },
  content: { padding: spacing.lg, paddingBottom: spacing['4xl'] },
  loadingContainer: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: colors.bgBase },
  welcomeRow: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    marginBottom: spacing['2xl'], paddingVertical: spacing.sm,
  },
  welcomeText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted },
  emailText: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, marginTop: spacing.xs },
  statusDot: { width: 10, height: 10, borderRadius: 5 },
  metricsGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.md, marginBottom: spacing['3xl'] },
  statCard: {
    width: '47.5%', backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg,
    padding: spacing.lg, borderWidth: 1, borderColor: colors.bgBorder,
    borderTopWidth: 3,
  },
  statHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: spacing.md },
  statLabel: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textSecondary, fontWeight: '500' },
  statIconWrap: { width: 36, height: 36, borderRadius: borderRadius.md, alignItems: 'center', justifyContent: 'center' },
  statValue: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '700' },
  statSublabel: { fontFamily: 'monospace', fontSize: fontSizes['2xs'], color: colors.textMuted, marginTop: spacing.xs },
  sectionTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.lg },
  fileRow: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.lg, marginBottom: spacing.sm,
    borderWidth: 1, borderColor: colors.bgBorder,
    flexDirection: 'row', alignItems: 'center',
  },
  fileRowBlocked: { borderLeftWidth: 3, borderLeftColor: colors.threat },
  fileMain: { flex: 1, marginRight: spacing.md },
  fileName: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500' },
  fileMeta: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xs },
  fileRight: { alignItems: 'flex-end', gap: spacing.xs },
  badge: { paddingHorizontal: spacing.sm, paddingVertical: 2, borderRadius: borderRadius.sm },
  badgeText: { fontFamily: 'monospace', fontSize: fontSizes['2xs'], fontWeight: '700', letterSpacing: 0.5 },
  riskText: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600' },
  emptyState: { alignItems: 'center', paddingVertical: spacing['4xl'] },
  emptyTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, color: colors.textSecondary, marginTop: spacing.lg, fontWeight: '500' },
  emptyText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, marginTop: spacing.xs },
});
