import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity, RefreshControl, ActivityIndicator, Alert,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import api from '../services/api';

export default function SharedFilesScreen() {
  const [shares, setShares] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedShare, setSelectedShare] = useState<any>(null);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const { addToast } = useToast();

  const fetchShares = useCallback(async () => {
    try {
      const data = await api.getShares();
      setShares(data.shares || []);
    } catch (err: any) {
      if (err.status !== 401) addToast('Failed to load shared links', 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchShares();
    const interval = setInterval(fetchShares, 15000);
    return () => clearInterval(interval);
  }, [fetchShares]);

  const handleSharePress = async (share: any) => {
    setSelectedShare(share);
    setLoadingAudit(true);
    try {
      const data = await api.getShareAudit(share.id);
      setAuditLogs(data.audit || data.logs || []);
    } catch {
      addToast('Failed to load access logs', 'error');
    } finally {
      setLoadingAudit(false);
    }
  };

  const handleCopy = async (share: any) => {
    const url = `https://yourdomain.com/s/${share.token}`;
    await Clipboard.setStringAsync(url);
    addToast('Share link copied!', 'success');
  };

  const handleRevoke = (shareId: string) => {
    Alert.alert('Revoke Share', 'Recipients will immediately lose access.', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Revoke', style: 'destructive',
        onPress: async () => {
          try {
            await api.revokeShare(shareId);
            addToast('Share link revoked', 'success');
            setSelectedShare(null);
            fetchShares();
          } catch (err: any) {
            addToast(err.message || 'Failed to revoke', 'error');
          }
        },
      },
    ]);
  };

  const getStatusColor = (share: any) => {
    if (share.status === 'revoked') return colors.threat;
    if (new Date(share.expiresAt) < new Date() || share.status === 'expired') return colors.queue;
    return colors.safe;
  };

  const getStatusText = (share: any) => {
    if (share.status === 'revoked') return 'Revoked';
    if (new Date(share.expiresAt) < new Date() || share.status === 'expired') return 'Expired';
    return 'Active';
  };

  // Detail view
  if (selectedShare) {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <TouchableOpacity onPress={() => setSelectedShare(null)} style={styles.backBtn}>
          <Ionicons name="arrow-back" size={20} color={colors.accent} />
          <Text style={styles.backText}>Back to Shares</Text>
        </TouchableOpacity>

        <View style={styles.detailCard}>
          <Text style={styles.detailTitle}>Manage Shared Link</Text>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>File</Text>
            <Text style={styles.detailValue}>{selectedShare.fileName}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Created</Text>
            <Text style={styles.detailValue}>{new Date(selectedShare.createdAt).toLocaleString()}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Expires</Text>
            <Text style={styles.detailValue}>{new Date(selectedShare.expiresAt).toLocaleString()}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Downloads</Text>
            <Text style={styles.detailValue}>
              {selectedShare.downloads} / {selectedShare.maxDownloads === -1 ? 'Unlimited' : selectedShare.maxDownloads}
            </Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Protection</Text>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: spacing.xs }}>
              <Ionicons
                name={selectedShare.passwordProtected ? 'lock-closed' : 'lock-open'}
                size={14}
                color={selectedShare.passwordProtected ? colors.safe : colors.textMuted}
              />
              <Text style={styles.detailValue}>
                {selectedShare.passwordProtected ? 'Password' : 'Open'}
              </Text>
            </View>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Status</Text>
            <Text style={[styles.detailValue, { color: getStatusColor(selectedShare), fontWeight: '700' }]}>
              {getStatusText(selectedShare)}
            </Text>
          </View>
        </View>

        {/* Actions */}
        <View style={styles.actionRow}>
          <TouchableOpacity style={styles.copyBtn} onPress={() => handleCopy(selectedShare)}>
            <Ionicons name="copy" size={16} color={colors.accent} />
            <Text style={styles.copyBtnText}>Copy Link</Text>
          </TouchableOpacity>
          {selectedShare.status === 'active' && new Date(selectedShare.expiresAt) > new Date() && (
            <TouchableOpacity style={styles.revokeBtn} onPress={() => handleRevoke(selectedShare.id)}>
              <Ionicons name="trash" size={16} color={colors.threat} />
              <Text style={styles.revokeBtnText}>Revoke</Text>
            </TouchableOpacity>
          )}
        </View>

        {/* Audit logs */}
        <Text style={[styles.sectionTitle, { marginTop: spacing['2xl'] }]}>Access & Audit Trail</Text>
        {loadingAudit ? (
          <ActivityIndicator size="small" color={colors.accent} style={{ padding: spacing.xl }} />
        ) : auditLogs.length === 0 ? (
          <Text style={styles.noAudit}>No access attempts recorded yet.</Text>
        ) : (
          auditLogs.map((log: any) => (
            <View key={log.id} style={styles.auditItem}>
              <View style={[
                styles.auditIcon,
                {
                  backgroundColor: log.event?.includes('download')
                    ? `${colors.safe}15`
                    : (log.event?.includes('wrong') || log.event?.includes('fail'))
                      ? `${colors.threat}15`
                      : `${colors.scan}15`
                }
              ]}>
                <Ionicons
                  name={log.event?.includes('download') ? 'download' : log.event?.includes('wrong') ? 'shield-half' : 'time'}
                  size={14}
                  color={log.event?.includes('download') ? colors.safe : log.event?.includes('wrong') ? colors.threat : colors.scan}
                />
              </View>
              <View style={{ flex: 1 }}>
                <View style={styles.auditTop}>
                  <Text style={styles.auditEvent}>{log.event?.replace('_', ' ').toUpperCase()}</Text>
                  <Text style={styles.auditTime}>{new Date(log.timestamp).toLocaleTimeString()}</Text>
                </View>
                <Text style={styles.auditDetails}>{log.details}</Text>
                <Text style={styles.auditIp}>IP: {log.ipAddress}</Text>
              </View>
            </View>
          ))
        )}
      </ScrollView>
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); fetchShares(); }} tintColor={colors.accent} />}
    >
      <Text style={styles.pageTitle}>Shared Files</Text>
      <Text style={styles.pageDesc}>Monitor external file access, revoke links, and review logs</Text>

      {loading ? (
        <ActivityIndicator size="large" color={colors.accent} style={{ marginTop: spacing['4xl'] }} />
      ) : shares.length === 0 ? (
        <View style={styles.emptyState}>
          <Ionicons name="alert-circle-outline" size={48} color={colors.textMuted} />
          <Text style={styles.emptyTitle}>No active share links</Text>
          <Text style={styles.emptyText}>Go to File History, open a file and tap "Share" to create one.</Text>
        </View>
      ) : (
        shares.map(share => (
          <TouchableOpacity key={share.id} style={styles.shareRow} onPress={() => handleSharePress(share)} activeOpacity={0.7}>
            <View style={{ flex: 1 }}>
              <Text style={styles.shareFile} numberOfLines={1}>{share.fileName}</Text>
              <Text style={styles.shareMeta}>
                {share.downloads}/{share.maxDownloads === -1 ? '∞' : share.maxDownloads} downloads
                {share.passwordProtected ? ' · 🔒 Secure' : ' · Open'}
              </Text>
            </View>
            <View style={styles.shareRight}>
              <Text style={[styles.shareStatus, { color: getStatusColor(share) }]}>{getStatusText(share)}</Text>
              <TouchableOpacity onPress={() => handleCopy(share)} hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}>
                <Ionicons name="copy-outline" size={18} color={colors.textMuted} />
              </TouchableOpacity>
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
  pageTitle: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.sm },
  pageDesc: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, lineHeight: 22, marginBottom: spacing['2xl'] },
  emptyState: { alignItems: 'center', paddingVertical: spacing['4xl'] },
  emptyTitle: { fontFamily: 'monospace', fontSize: fontSizes.base, color: colors.textSecondary, marginTop: spacing.lg, fontWeight: '500' },
  emptyText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, marginTop: spacing.xs, textAlign: 'center' },
  shareRow: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.lg, marginBottom: spacing.sm,
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  shareFile: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500' },
  shareMeta: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xs },
  shareRight: { alignItems: 'flex-end', gap: spacing.sm },
  shareStatus: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '700' },
  backBtn: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm, marginBottom: spacing.xl },
  backText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent },
  detailCard: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg,
    padding: spacing.xl, borderWidth: 1, borderColor: colors.bgBorder,
  },
  detailTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.xl },
  detailRow: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingVertical: spacing.md, borderBottomWidth: 1, borderBottomColor: colors.bgBorder,
  },
  detailLabel: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  detailValue: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary },
  actionRow: { flexDirection: 'row', gap: spacing.md, marginTop: spacing.xl },
  copyBtn: {
    flex: 1, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.shareBg, borderWidth: 1, borderColor: colors.shareBorder,
    paddingVertical: spacing.md, borderRadius: borderRadius.md,
  },
  copyBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent, fontWeight: '600' },
  revokeBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.threatBg, borderWidth: 1, borderColor: colors.threatBorder,
    paddingHorizontal: spacing.xl, paddingVertical: spacing.md, borderRadius: borderRadius.md,
  },
  revokeBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.threat, fontWeight: '600' },
  sectionTitle: { fontFamily: 'monospace', fontSize: fontSizes.base, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.md },
  noAudit: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, textAlign: 'center', padding: spacing.xl },
  auditItem: {
    flexDirection: 'row', gap: spacing.md,
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.md, marginBottom: spacing.sm,
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  auditIcon: { width: 30, height: 30, borderRadius: borderRadius.full, alignItems: 'center', justifyContent: 'center' },
  auditTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  auditEvent: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600', color: colors.textPrimary },
  auditTime: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  auditDetails: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textSecondary, marginTop: spacing.xs },
  auditIp: { fontFamily: 'monospace', fontSize: fontSizes['2xs'], color: colors.textMuted, marginTop: spacing.xs },
});
