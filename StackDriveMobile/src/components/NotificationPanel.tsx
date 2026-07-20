import React, { useState, useEffect } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  ActivityIndicator, Modal,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import api from '../services/api';

interface NotificationPanelProps {
  visible: boolean;
  onClose: () => void;
  onRefreshBadge?: () => void;
}

export default function NotificationPanel({ visible, onClose, onRefreshBadge }: NotificationPanelProps) {
  const [notifications, setNotifications] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchNotifications = async () => {
    try {
      const data = await api.getNotifications();
      setNotifications(data.notifications || []);
    } catch (e) {
      console.error('Failed to fetch notifications', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (visible) {
      fetchNotifications();
    }
  }, [visible]);

  const handleMarkRead = async () => {
    try {
      await api.markNotificationsRead();
      setNotifications(notifications.map(n => ({ ...n, read: true })));
      onRefreshBadge?.();
    } catch (e) {
      console.error('Failed to mark read', e);
    }
  };

  function getRelativeTime(isoStr: string) {
    const date = new Date(isoStr);
    const diff = (Date.now() - date.getTime()) / 1000;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <Modal
      visible={visible}
      animationType="slide"
      transparent={true}
      onRequestClose={onClose}
    >
      <View style={styles.modalOverlay}>
        <View style={styles.container}>
          {/* Header */}
          <View style={styles.header}>
            <View style={styles.headerTitleWrap}>
              <Ionicons name="notifications-outline" size={20} color={colors.accent} />
              <Text style={styles.title}>Notifications</Text>
            </View>
            <View style={styles.headerActions}>
              {unreadCount > 0 && (
                <TouchableOpacity style={styles.markReadBtn} onPress={handleMarkRead}>
                  <Text style={styles.markReadText}>Mark all read</Text>
                </TouchableOpacity>
              )}
              <TouchableOpacity style={styles.closeBtn} onPress={onClose}>
                <Ionicons name="close" size={22} color={colors.textSecondary} />
              </TouchableOpacity>
            </View>
          </View>

          {/* List */}
          <ScrollView contentContainerStyle={styles.scrollContent}>
            {loading ? (
              <View style={styles.loadingWrap}>
                <ActivityIndicator size="small" color={colors.accent} />
                <Text style={styles.loadingText}>Loading notifications...</Text>
              </View>
            ) : notifications.length === 0 ? (
              <View style={styles.emptyWrap}>
                <View style={styles.emptyIconBg}>
                  <Ionicons name="mail-open-outline" size={40} color={colors.textMuted} />
                </View>
                <Text style={styles.emptyTitle}>All Clear</Text>
                <Text style={styles.emptyText}>No recent threats detected in your ingestion pipeline.</Text>
              </View>
            ) : (
              notifications.map((n) => {
                const isSafe = n.threatType.includes('SAFE');
                return (
                  <View key={n.id} style={[styles.item, !n.read && styles.itemUnread]}>
                    <View style={[styles.iconBg, isSafe ? styles.iconBgSafe : styles.iconBgThreat]}>
                      <Ionicons
                        name={isSafe ? "shield-checkmark-outline" : "shield-outline"}
                        size={16}
                        color={isSafe ? colors.safe : colors.threat}
                      />
                    </View>
                    <View style={styles.content}>
                      <View style={styles.itemHeader}>
                        <Text style={styles.filename} numberOfLines={1}>
                          {n.fileName}
                        </Text>
                        <Text style={styles.time}>{getRelativeTime(n.detectedAt)}</Text>
                      </View>
                      <Text style={styles.detail}>
                        <Text style={isSafe ? styles.textSafe : styles.textThreat}>
                          {n.threatType}
                        </Text>
                        {' — detected by '}
                        <Text style={styles.layerText}>{n.layer}</Text>
                      </Text>
                    </View>
                  </View>
                );
              })
            )}
          </ScrollView>
        </View>
      </View>
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
    height: '70%',
    backgroundColor: colors.bgSurface,
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
    backgroundColor: colors.bgElevated,
  },
  headerTitleWrap: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
  },
  title: {
    fontFamily: 'monospace',
    fontSize: fontSizes.base,
    fontWeight: '600',
    color: colors.textPrimary,
  },
  headerActions: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  markReadBtn: {
    paddingVertical: spacing.xs,
    paddingHorizontal: spacing.sm,
    borderRadius: borderRadius.sm,
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
  },
  markReadText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.accent,
    fontWeight: '600',
  },
  closeBtn: {
    padding: spacing.xs,
  },
  scrollContent: {
    padding: spacing.lg,
    flexGrow: 1,
  },
  loadingWrap: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingVertical: spacing['3xl'],
  },
  loadingText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textMuted,
    marginTop: spacing.md,
  },
  emptyWrap: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingVertical: spacing['3xl'],
    paddingHorizontal: spacing.xl,
  },
  emptyIconBg: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: colors.bgElevated,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: spacing.lg,
    borderWidth: 1,
    borderColor: colors.bgBorder,
  },
  emptyTitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.lg,
    fontWeight: '600',
    color: colors.textPrimary,
    marginBottom: spacing.xs,
  },
  emptyText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textMuted,
    textAlign: 'center',
    lineHeight: 20,
  },
  item: {
    flexDirection: 'row',
    padding: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.bgElevated,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    marginBottom: spacing.md,
    gap: spacing.md,
  },
  itemUnread: {
    borderColor: 'rgba(59, 130, 246, 0.3)',
    backgroundColor: 'rgba(59, 130, 246, 0.03)',
  },
  iconBg: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.sm,
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconBgSafe: {
    backgroundColor: 'rgba(34, 197, 94, 0.1)',
  },
  iconBgThreat: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
  },
  content: {
    flex: 1,
  },
  itemHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: spacing.xs,
  },
  filename: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    fontWeight: '600',
    color: colors.textPrimary,
    flex: 1,
    marginRight: spacing.sm,
  },
  time: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
  },
  detail: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
    lineHeight: 16,
  },
  textSafe: {
    color: colors.safe,
    fontWeight: '600',
  },
  textThreat: {
    color: colors.threat,
    fontWeight: '600',
  },
  layerText: {
    color: colors.textPrimary,
  },
});
