import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity, RefreshControl, ActivityIndicator, Alert,
  Modal, TextInput, Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { downloadAsync, documentDirectory, readAsStringAsync } from 'expo-file-system/legacy';
import * as Sharing from 'expo-sharing';
import * as Clipboard from 'expo-clipboard';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import api from '../services/api';

const filterTabs = ['all', 'safe', 'blocked', 'scanning', 'quarantine'];

function StatusBadge({ status }: { status: string }) {
  const config: any = {
    safe: { label: 'SAFE', color: colors.safe },
    blocked: { label: 'BLOCKED', color: colors.threat },
    scanning: { label: 'SCANNING', color: colors.scan },
    quarantine: { label: 'QUARANTINE', color: colors.queue },
  };
  const c = config[status] || { label: status?.toUpperCase(), color: colors.textMuted };
  return (
    <View style={[styles.badge, { backgroundColor: `${c.color}20` }]}>
      <Text style={[styles.badgeText, { color: c.color }]}>{c.label}</Text>
    </View>
  );
}

function getRelativeTime(dateInput: string) {
  if (!dateInput) return '—';
  const date = new Date(dateInput);
  if (isNaN(date.getTime())) return '—';
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function FileHistoryScreen() {
  const [activeFilter, setActiveFilter] = useState('all');
  const [files, setFiles] = useState<any[]>([]);
  const [allFiles, setAllFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<any>(null);
  const { addToast } = useToast();

  // Share link configurations
  const [shareModalVisible, setShareModalVisible] = useState(false);
  const [shareExpiry, setShareExpiry] = useState('24h');
  const [shareLimit, setShareLimit] = useState(-1);
  const [sharePassword, setSharePassword] = useState('');
  const [isSharing, setIsSharing] = useState(false);
  const [generatedLink, setGeneratedLink] = useState('');

  const fetchFiles = useCallback(async () => {
    try {
      const data = await api.getFiles(activeFilter);
      setFiles(data.files || []);
      if (activeFilter === 'all') setAllFiles(data.files || []);
    } catch (err: any) {
      if (err.status !== 401) addToast('Failed to load files', 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeFilter, addToast]);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const data = await api.getFiles('all');
        setAllFiles(data.files || []);
      } catch { /* ignore */ }
    };
    fetchAll();
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchFiles();
  }, [fetchFiles]);

  useEffect(() => {
    const interval = setInterval(fetchFiles, 10000);
    return () => clearInterval(interval);
  }, [fetchFiles]);

  const getCount = (status: string) => {
    if (status === 'all') return allFiles.length;
    return allFiles.filter(f => f.status === status).length;
  };

  const handleFilePress = async (file: any) => {
    try {
      const data = await api.getFile(file.id);
      setSelectedFile(data.file);
    } catch {
      setSelectedFile(file);
    }
  };

  const handleDelete = async (file: any) => {
    Alert.alert('Delete File', `Are you sure you want to delete "${file.name}"?`, [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete', style: 'destructive',
        onPress: async () => {
          try {
            await api.deleteFile(file.id);
            addToast(`${file.name} deleted`, 'success');
            setSelectedFile(null);
            fetchFiles();
          } catch (err: any) {
            addToast(err.message || 'Delete failed', 'error');
          }
        },
      },
    ]);
  };

  const handleDownload = async (file: any) => {
    try {
      const token = await api.getToken();
      const downloadUrl = api.getDownloadUrl(file.id);
      const fileUri = `${documentDirectory}${file.name}`;
      
      addToast('Downloading and decrypting...', 'info');
      
      const result = await downloadAsync(downloadUrl, fileUri, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (result.status !== 200) {
        let errMsg = 'Download failed';
        try {
          const content = await readAsStringAsync(fileUri);
          const data = JSON.parse(content);
          errMsg = data.error || errMsg;
        } catch { /* ignore */ }
        throw new Error(errMsg);
      }

      const warning = result.headers['X-Decryption-Warning'] || result.headers['x-decryption-warning'];
      if (warning) {
        addToast(`SECURITY WARNING: ${warning}`, 'warning', 6000);
      } else {
        addToast('File downloaded and decrypted successfully!', 'success');
      }

      if (await Sharing.isAvailableAsync()) {
        await Sharing.shareAsync(fileUri);
      } else {
        addToast(`File saved to local storage`, 'info');
      }
    } catch (err: any) {
      addToast(err.message || 'Download failed', 'error');
    }
  };

  const handleShare = async () => {
    if (!selectedFile) return;
    setIsSharing(true);
    try {
      const data = await api.createShareLink(selectedFile.id, {
        expires_in: shareExpiry,
        max_downloads: shareLimit,
        password: sharePassword.trim() || null,
      });
      const webBase = api.getWebBase();
      const shareUrl = `${webBase}/s/${data.token}`;
      setGeneratedLink(shareUrl);
      addToast('Secure share link created!', 'success');
    } catch (err: any) {
      addToast(err.message || 'Failed to create share link', 'error');
    } finally {
      setIsSharing(false);
    }
  };

  const onRefresh = () => {
    setRefreshing(true);
    fetchFiles();
  };

  // File detail view
  if (selectedFile) {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <TouchableOpacity onPress={() => setSelectedFile(null)} style={styles.backBtn}>
          <Ionicons name="arrow-back" size={20} color={colors.accent} />
          <Text style={styles.backText}>Back to Files</Text>
        </TouchableOpacity>

        <View style={styles.detailCard}>
          <Text style={styles.detailTitle}>File Details</Text>

          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>File Name</Text>
            <Text style={styles.detailValue}>{selectedFile.name}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Size</Text>
            <Text style={styles.detailValue}>{selectedFile.size} {selectedFile.sizeUnit}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Uploaded</Text>
            <Text style={styles.detailValue}>{new Date(selectedFile.uploadedAt).toLocaleString()}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Status</Text>
            <StatusBadge status={selectedFile.status} />
          </View>
          {selectedFile.risk !== null && selectedFile.risk !== undefined && (
            <View style={styles.detailRow}>
              <Text style={styles.detailLabel}>Risk Score</Text>
              <Text style={[styles.detailValue, {
                color: selectedFile.risk < 10 ? colors.safe : selectedFile.risk <= 60 ? colors.queue : colors.threat
              }]}>{selectedFile.risk}%</Text>
            </View>
          )}
          {selectedFile.sha256 && (
            <View style={styles.detailRow}>
              <Text style={styles.detailLabel}>SHA-256</Text>
              <Text style={[styles.detailValue, { fontSize: fontSizes['2xs'] }]} selectable>{selectedFile.sha256}</Text>
            </View>
          )}

          {/* Pipeline stages */}
          {selectedFile.pipelineStages?.length > 0 && (
            <>
              <View style={styles.separator} />
              <Text style={styles.sectionLabel}>Pipeline Results</Text>
              {selectedFile.pipelineStages.map((stage: any, i: number) => (
                <View key={i} style={styles.stageRow}>
                  <View style={[styles.stageDot, {
                    backgroundColor: stage.status === 'pass' ? colors.pass : stage.status === 'fail' ? colors.threat : colors.textMuted
                  }]} />
                  <Text style={styles.stageName}>{stage.name}</Text>
                  <Text style={[styles.stageStatus, {
                    color: stage.status === 'pass' ? colors.pass : stage.status === 'fail' ? colors.threat : colors.textMuted
                  }]}>{stage.status.toUpperCase()}</Text>
                </View>
              ))}
            </>
          )}

          {/* Encryption Metadata */}
          {selectedFile.status === 'safe' && (
            <>
              <View style={styles.separator} />
              <Text style={styles.sectionLabel}>Encryption Metadata</Text>
              <View style={styles.detailRow}>
                <Text style={styles.detailLabel}>Algorithm</Text>
                <Text style={styles.detailValue}>AES-256-GCM</Text>
              </View>
              <View style={styles.detailRow}>
                <Text style={styles.detailLabel}>Key Mgmt</Text>
                <Text style={styles.detailValue}>AWS KMS (CMK)</Text>
              </View>
              <View style={styles.detailRow}>
                <Text style={styles.detailLabel}>PQ Wrapping</Text>
                <Text style={styles.detailValue}>Kyber-1024</Text>
              </View>
              <View style={styles.detailRow}>
                <Text style={styles.detailLabel}>Signature</Text>
                <Text style={styles.detailValue}>Dilithium-3</Text>
              </View>
            </>
          )}
        </View>

        {/* Action buttons */}
        <View style={styles.actionRow}>
          {selectedFile.status === 'safe' ? (
            <>
              <TouchableOpacity style={styles.shareBtn} onPress={() => setShareModalVisible(true)}>
                <Ionicons name="share-social" size={16} color={colors.accent} />
                <Text style={styles.shareBtnText}>Share</Text>
              </TouchableOpacity>
              
              <TouchableOpacity style={styles.downloadBtn} onPress={() => handleDownload(selectedFile)}>
                <Ionicons name="download" size={16} color="#fff" />
                <Text style={styles.downloadBtnText}>Download</Text>
              </TouchableOpacity>

              <TouchableOpacity style={styles.deleteBtn} onPress={() => handleDelete(selectedFile)}>
                <Ionicons name="trash" size={16} color={colors.threat} />
                <Text style={styles.deleteBtnText}>Delete</Text>
              </TouchableOpacity>
            </>
          ) : (
            <TouchableOpacity style={styles.deleteBtn} onPress={() => handleDelete(selectedFile)}>
              <Ionicons name="trash" size={16} color={colors.threat} />
              <Text style={styles.deleteBtnText}>Delete</Text>
            </TouchableOpacity>
          )}
        </View>

        {/* Secure Link Share Configuration Modal */}
        <Modal
          visible={shareModalVisible}
          animationType="fade"
          transparent={true}
          onRequestClose={() => {
            setShareModalVisible(false);
            setGeneratedLink('');
            setSharePassword('');
          }}
        >
          <View style={styles.modalOverlay}>
            <View style={styles.modalContainer}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Share File</Text>
                <TouchableOpacity onPress={() => {
                  setShareModalVisible(false);
                  setGeneratedLink('');
                  setSharePassword('');
                }}>
                  <Ionicons name="close" size={24} color={colors.textSecondary} />
                </TouchableOpacity>
              </View>

              {generatedLink ? (
                <View style={styles.modalContent}>
                  <Text style={styles.modalSubtitle}>Secure link generated successfully!</Text>
                  <View style={styles.linkContainer}>
                    <Text style={styles.linkText} numberOfLines={1}>{generatedLink}</Text>
                  </View>
                  <View style={styles.modalActions}>
                    <TouchableOpacity
                      style={styles.copyBtn}
                      onPress={async () => {
                        await Clipboard.setStringAsync(generatedLink);
                        addToast('Copied to clipboard!', 'success');
                      }}
                    >
                      <Ionicons name="copy" size={16} color="#fff" />
                      <Text style={styles.copyBtnText}>Copy Link</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={styles.shareSheetBtn}
                      onPress={async () => {
                        if (await Sharing.isAvailableAsync()) {
                          await Sharing.shareAsync(generatedLink);
                        }
                      }}
                    >
                      <Ionicons name="share-social" size={16} color="#fff" />
                      <Text style={styles.shareSheetBtnText}>Share Link</Text>
                    </TouchableOpacity>
                  </View>
                </View>
              ) : (
                <View style={styles.modalContent}>
                  <Text style={styles.inputLabel}>Link Expiration</Text>
                  <View style={styles.optionsRow}>
                    {['1h', '24h', '7d'].map((val) => (
                      <TouchableOpacity
                        key={val}
                        style={[styles.optionBtn, shareExpiry === val && styles.optionBtnActive]}
                        onPress={() => setShareExpiry(val)}
                      >
                        <Text style={[styles.optionBtnText, shareExpiry === val && styles.optionBtnTextActive]}>
                          {val === '1h' ? '1 Hour' : val === '24h' ? '1 Day' : '7 Days'}
                        </Text>
                      </TouchableOpacity>
                    ))}
                  </View>

                  <Text style={styles.inputLabel}>Download Limit</Text>
                  <View style={styles.optionsRow}>
                    {[-1, 1, 5].map((val) => (
                      <TouchableOpacity
                        key={val}
                        style={[styles.optionBtn, shareLimit === val && styles.optionBtnActive]}
                        onPress={() => setShareLimit(val)}
                      >
                        <Text style={[styles.optionBtnText, shareLimit === val && styles.optionBtnTextActive]}>
                          {val === -1 ? 'Unlimited' : val === 1 ? '1 Time' : '5 Times'}
                        </Text>
                      </TouchableOpacity>
                    ))}
                  </View>

                  <Text style={styles.inputLabel}>Password Protection (Optional)</Text>
                  <TextInput
                    style={styles.textInput}
                    value={sharePassword}
                    onChangeText={setSharePassword}
                    placeholder="Enter access password"
                    placeholderTextColor={colors.textMuted}
                    secureTextEntry
                  />

                  <TouchableOpacity
                    style={styles.generateBtn}
                    onPress={handleShare}
                    disabled={isSharing}
                  >
                    {isSharing ? (
                      <ActivityIndicator size="small" color="#fff" />
                    ) : (
                      <>
                        <Ionicons name="link" size={16} color="#fff" />
                        <Text style={styles.generateBtnText}>Generate Secure Link</Text>
                      </>
                    )}
                  </TouchableOpacity>
                </View>
              )}
            </View>
          </View>
        </Modal>
      </ScrollView>
    );
  }

  return (
    <View style={styles.container}>
      {/* Filter tabs */}
      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.filterScroll} contentContainerStyle={styles.filterContainer}>
        {filterTabs.map(tab => (
          <TouchableOpacity
            key={tab}
            style={[styles.filterTab, activeFilter === tab && styles.filterTabActive]}
            onPress={() => setActiveFilter(tab)}
          >
            <Text style={[styles.filterTabText, activeFilter === tab && styles.filterTabTextActive]}>
              {tab.toUpperCase()}
            </Text>
            <View style={[styles.filterCount, activeFilter === tab && styles.filterCountActive]}>
              <Text style={[styles.filterCountText, activeFilter === tab && styles.filterCountTextActive]}>
                {getCount(tab)}
              </Text>
            </View>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* File list */}
      <ScrollView
        style={{ flex: 1 }}
        contentContainerStyle={{ padding: spacing.lg, paddingBottom: spacing['4xl'] }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.accent} />}
      >
        {loading ? (
          <View style={styles.loadingWrap}>
            <ActivityIndicator size="large" color={colors.accent} />
          </View>
        ) : files.length === 0 ? (
          <View style={styles.emptyState}>
            <Ionicons name="folder-open-outline" size={48} color={colors.textMuted} />
            <Text style={styles.emptyTitle}>No files found</Text>
          </View>
        ) : (
          files.map((file: any) => (
            <TouchableOpacity
              key={file.id}
              style={[styles.fileRow, file.status === 'blocked' && styles.fileRowBlocked]}
              onPress={() => handleFilePress(file)}
              activeOpacity={0.7}
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
                  <Text style={[styles.riskText, {
                    color: file.risk < 10 ? colors.safe : file.risk <= 60 ? colors.queue : colors.threat
                  }]}>{file.risk}%</Text>
                )}
              </View>
            </TouchableOpacity>
          ))
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgBase },
  content: { padding: spacing.lg, paddingBottom: spacing['4xl'] },
  filterScroll: { maxHeight: 56 },
  filterContainer: {
    flexDirection: 'row', gap: spacing.sm, paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md, backgroundColor: colors.bgSurface,
    borderBottomWidth: 1, borderBottomColor: colors.bgBorder,
  },
  filterTab: {
    flexDirection: 'row', alignItems: 'center', gap: spacing.xs,
    paddingHorizontal: spacing.md, paddingVertical: spacing.sm,
    borderRadius: borderRadius.md, backgroundColor: 'transparent',
  },
  filterTabActive: { backgroundColor: colors.bgElevated },
  filterTabText: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600', color: colors.textMuted, letterSpacing: 0.5 },
  filterTabTextActive: { color: colors.textPrimary },
  filterCount: {
    paddingHorizontal: spacing.xs, paddingVertical: 1,
    borderRadius: borderRadius.sm, backgroundColor: colors.bgBorder,
  },
  filterCountActive: { backgroundColor: colors.accent },
  filterCountText: { fontFamily: 'monospace', fontSize: fontSizes['2xs'], color: colors.textMuted, fontWeight: '600' },
  filterCountTextActive: { color: '#fff' },
  loadingWrap: { paddingVertical: spacing['4xl'], alignItems: 'center' },
  emptyState: { alignItems: 'center', paddingVertical: spacing['4xl'] },
  emptyTitle: { fontFamily: 'monospace', fontSize: fontSizes.base, color: colors.textMuted, marginTop: spacing.lg },
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
  riskText: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600' },
  badge: { paddingHorizontal: spacing.sm, paddingVertical: 2, borderRadius: borderRadius.sm },
  badgeText: { fontFamily: 'monospace', fontSize: fontSizes['2xs'], fontWeight: '700', letterSpacing: 0.5 },
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
  detailValue: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500', flex: 1, textAlign: 'right', marginLeft: spacing.lg },
  separator: { height: 1, backgroundColor: colors.bgBorder, marginVertical: spacing.xl },
  sectionLabel: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.md },
  stageRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm, paddingVertical: spacing.sm },
  stageDot: { width: 8, height: 8, borderRadius: 4 },
  stageName: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, flex: 1 },
  stageStatus: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '700' },
  
  // Modal & Button styling matching the theme
  actionRow: {
    flexDirection: 'row',
    gap: spacing.sm,
    marginTop: spacing.xl,
    justifyContent: 'space-between',
  },
  deleteBtn: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
    backgroundColor: colors.threatBg,
    borderWidth: 1,
    borderColor: colors.threatBorder,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
  },
  deleteBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.threat, fontWeight: '600' },
  shareBtn: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(59, 130, 246, 0.2)',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
  },
  shareBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.accent,
    fontWeight: '600',
  },
  downloadBtn: {
    flex: 1.2,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
    backgroundColor: colors.accent,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
  },
  downloadBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: '#fff',
    fontWeight: '600',
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: spacing.xl,
  },
  modalContainer: {
    width: '100%',
    backgroundColor: colors.bgSurface,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    overflow: 'hidden',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.lg,
    borderBottomWidth: 1,
    borderBottomColor: colors.bgBorder,
  },
  modalTitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.base,
    fontWeight: '700',
    color: colors.textPrimary,
  },
  modalContent: {
    padding: spacing.xl,
    gap: spacing.md,
  },
  modalSubtitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.safe,
    textAlign: 'center',
    marginBottom: spacing.xs,
  },
  inputLabel: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
    marginBottom: 2,
  },
  optionsRow: {
    flexDirection: 'row',
    gap: spacing.sm,
    marginBottom: spacing.xs,
  },
  optionBtn: {
    flex: 1,
    paddingVertical: spacing.sm,
    alignItems: 'center',
    borderRadius: borderRadius.md,
    backgroundColor: colors.bgBase,
    borderWidth: 1,
    borderColor: colors.bgBorder,
  },
  optionBtnActive: {
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    borderColor: colors.accent,
  },
  optionBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
  },
  optionBtnTextActive: {
    color: colors.accent,
    fontWeight: '600',
  },
  textInput: {
    backgroundColor: colors.bgBase,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    color: colors.textPrimary,
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    marginBottom: spacing.xs,
  },
  generateBtn: {
    flexDirection: 'row',
    backgroundColor: colors.accent,
    borderRadius: borderRadius.md,
    paddingVertical: spacing.md,
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
    marginTop: spacing.xs,
  },
  generateBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: '#fff',
    fontWeight: '600',
  },
  linkContainer: {
    backgroundColor: colors.bgBase,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    padding: spacing.md,
    marginBottom: spacing.xs,
  },
  linkText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textPrimary,
  },
  modalActions: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  copyBtn: {
    flex: 1,
    flexDirection: 'row',
    backgroundColor: '#06b6d4',
    borderRadius: borderRadius.md,
    paddingVertical: spacing.md,
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
  },
  copyBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: '#fff',
    fontWeight: '600',
  },
  shareSheetBtn: {
    flex: 1,
    flexDirection: 'row',
    backgroundColor: colors.accent,
    borderRadius: borderRadius.md,
    paddingVertical: spacing.md,
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
  },
  shareSheetBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: '#fff',
    fontWeight: '600',
  },
});
