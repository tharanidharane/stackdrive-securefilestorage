import React, { useState, useCallback, useRef } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity, ActivityIndicator, Platform,
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

export default function UploadScreen() {
  const { addToast } = useToast();
  const { user } = useAuth();
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [fileName, setFileName] = useState('');
  const [recentUploads, setRecentUploads] = useState<any[]>([]);
  const [pipelineData, setPipelineData] = useState<any>(null);
  const pollingRef = useRef<any>(null);
  const awsConnected = user?.aws_connected !== false;

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    const mb = kb / 1024;
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    return `${(mb / 1024).toFixed(1)} GB`;
  };

  const pollPipeline = useCallback(async (fileId: string, name: string) => {
    setPipelineData({ stages: [], fileName: name, result: null, isActive: true });

    const poll = async () => {
      try {
        const data = await api.getPipeline(fileId);
        const stages = data.stages || [];
        const fileStatus = data.status;
        const isComplete = fileStatus === 'safe' || fileStatus === 'blocked';
        const result = fileStatus === 'safe' ? 'safe' : fileStatus === 'blocked' ? 'blocked' : null;

        setPipelineData({ stages, fileName: name, result, showBanner: isComplete, isActive: true });

        if (isComplete) {
          clearInterval(pollingRef.current);
          pollingRef.current = null;

          setRecentUploads(prev => prev.map(u =>
            u.fileId === fileId ? { ...u, status: fileStatus } : u
          ));

          if (fileStatus === 'safe') {
            addToast(`${name} verified and stored securely`, 'success');
          } else {
            addToast(`Threat detected in ${name}`, 'error');
          }
          setTimeout(() => setPipelineData(null), 8000);
        }
      } catch { /* keep polling */ }
    };

    await poll();
    pollingRef.current = setInterval(poll, 1500);
  }, [addToast]);

  const handlePickFile = async () => {
    if (!awsConnected) {
      addToast('Connect your AWS account first in Settings', 'warning');
      return;
    }

    try {
      const result = await DocumentPicker.getDocumentAsync({
        copyToCacheDirectory: true,
        type: '*/*',
      });

      if (result.canceled || !result.assets || result.assets.length === 0) return;

      const file = result.assets[0];
      if ((file.size || 0) > 500 * 1024 * 1024) {
        addToast('File size exceeds 500MB limit', 'error');
        return;
      }

      setUploading(true);
      setFileName(file.name);
      setProgress(0);

      const data = await api.uploadFileLocal(
        file.uri,
        file.name,
        file.size || 0,
        (pct) => setProgress(pct)
      );

      setProgress(100);
      const upload = {
        id: Date.now(),
        fileId: data.file?.id,
        name: file.name,
        size: formatFileSize(file.size || 0),
        time: new Date().toLocaleTimeString(),
        status: 'scanning',
      };
      setRecentUploads(prev => [upload, ...prev]);
      addToast(`${file.name} uploaded — pipeline starting`, 'info');

      setTimeout(() => {
        setUploading(false);
        setProgress(0);
        setFileName('');
      }, 500);

      if (data.file?.id) {
        pollPipeline(data.file.id, file.name);
      }
    } catch (err: any) {
      addToast(err.message || 'Upload failed', 'error');
      setUploading(false);
      setProgress(0);
      setFileName('');
    }
  };

  const getStageIcon = (name: string) => {
    if (name.includes('SHA') || name.includes('VirusTotal')) return 'finger-print';
    if (name.includes('Heuristic') || name.includes('Archive')) return 'archive';
    if (name.includes('ClamAV')) return 'bug';
    if (name.includes('Sandbox')) return 'cube';
    if (name.includes('Encrypt')) return 'lock-closed';
    return 'shield';
  };

  const getStageColor = (status: string) => {
    if (status === 'pass') return colors.pass;
    if (status === 'fail') return colors.threat;
    if (status === 'running') return colors.scan;
    return colors.textMuted;
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
      <Text style={styles.pageTitle}>Upload File</Text>
      <Text style={styles.pageDesc}>
        Pick a file from your device. It will be quarantined and scanned through our 4-layer security pipeline before being encrypted and stored.
      </Text>

      {/* Upload Zone */}
      <TouchableOpacity
        style={[
          styles.uploadZone,
          !awsConnected && styles.uploadZoneDisabled,
          uploading && styles.uploadZoneActive,
        ]}
        onPress={handlePickFile}
        disabled={uploading}
        activeOpacity={0.7}
      >
        {!awsConnected ? (
          <View style={styles.uploadContent}>
            <Ionicons name="lock-closed" size={48} color={colors.textMuted} />
            <Text style={styles.uploadText}>Connect AWS to start uploading</Text>
            <Text style={styles.uploadHint}>Go to Settings → Connect with AWS</Text>
          </View>
        ) : uploading ? (
          <View style={styles.uploadContent}>
            <Ionicons name="flash" size={24} color={colors.scan} />
            <Text style={styles.uploadFileName}>{fileName}</Text>
            <View style={styles.progressBar}>
              <View style={[styles.progressFill, { width: `${progress}%` }]} />
            </View>
            <Text style={styles.progressText}>{Math.round(progress)}% uploaded</Text>
          </View>
        ) : (
          <View style={styles.uploadContent}>
            <View style={styles.uploadIconBg}>
              <Ionicons name="cloud-upload" size={40} color={colors.accent} />
            </View>
            <Text style={styles.uploadText}>Tap to select a file</Text>
            <Text style={styles.uploadHint}>All file types · Up to 500MB</Text>
            <View style={styles.uploadSpeedBadge}>
              <Ionicons name="flash" size={12} color={colors.scan} />
              <Text style={styles.uploadSpeedText}>Direct-to-S3 multipart upload</Text>
            </View>
          </View>
        )}
      </TouchableOpacity>

      {/* Info Cards */}
      <View style={styles.infoGrid}>
        {[
          { title: 'Accepted', desc: 'All file types', icon: 'document-text' },
          { title: 'Security', desc: '4 automated checks', icon: 'shield-checkmark' },
          { title: 'Encryption', desc: 'AES-256 + Kyber PQ', icon: 'lock-closed' },
          { title: 'Alerts', desc: 'Real-time SMTP', icon: 'notifications' },
        ].map((item, i) => (
          <View key={i} style={styles.infoCard}>
            <Ionicons name={item.icon as any} size={18} color={colors.accent} />
            <Text style={styles.infoTitle}>{item.title}</Text>
            <Text style={styles.infoDesc}>{item.desc}</Text>
          </View>
        ))}
      </View>

      {/* Pipeline Panel */}
      {pipelineData && pipelineData.isActive && (
        <View style={styles.pipelinePanel}>
          <Text style={styles.pipelineTitle}>Security Pipeline</Text>
          <Text style={styles.pipelineFile}>{pipelineData.fileName}</Text>
          {pipelineData.stages.map((stage: any, i: number) => (
            <View key={stage.name} style={styles.pipelineStage}>
              <View style={[styles.pipelineDot, { backgroundColor: getStageColor(stage.status) }]} />
              <Ionicons name={getStageIcon(stage.name) as any} size={16} color={getStageColor(stage.status)} />
              <View style={styles.pipelineStageContent}>
                <Text style={styles.pipelineStageName}>{stage.name}</Text>
                <Text style={styles.pipelineStageDetail}>{stage.statusDetail || stage.detail}</Text>
              </View>
              <View style={[styles.stageStatus, { backgroundColor: `${getStageColor(stage.status)}20` }]}>
                <Text style={[styles.stageStatusText, { color: getStageColor(stage.status) }]}>
                  {stage.status?.toUpperCase()}
                </Text>
              </View>
            </View>
          ))}
          {pipelineData.showBanner && pipelineData.result && (
            <View style={[
              styles.pipelineBanner,
              { backgroundColor: pipelineData.result === 'safe' ? `${colors.safe}15` : `${colors.threat}15` }
            ]}>
              <Text style={[
                styles.pipelineBannerText,
                { color: pipelineData.result === 'safe' ? colors.safe : colors.threat }
              ]}>
                {pipelineData.result === 'safe' ? '✓ FILE VERIFIED — SAFE' : '✗ FILE REJECTED — BLOCKED'}
              </Text>
            </View>
          )}
        </View>
      )}

      {/* Recent Uploads */}
      {recentUploads.length > 0 && (
        <>
          <Text style={[styles.sectionTitle, { marginTop: spacing['2xl'] }]}>This Session</Text>
          {recentUploads.map((upload) => (
            <View key={upload.id} style={styles.recentItem}>
              <View style={{ flex: 1 }}>
                <Text style={styles.recentName}>{upload.name}</Text>
                <Text style={styles.recentMeta}>{upload.size} · {upload.time}</Text>
              </View>
              <Text style={[
                styles.recentStatus,
                {
                  color: upload.status === 'safe' ? colors.safe :
                    upload.status === 'blocked' ? colors.threat : colors.scan
                }
              ]}>
                {upload.status.toUpperCase()}
              </Text>
            </View>
          ))}
        </>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgBase },
  content: { padding: spacing.lg, paddingBottom: spacing['4xl'] },
  pageTitle: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.sm },
  pageDesc: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, lineHeight: 22, marginBottom: spacing['2xl'] },
  uploadZone: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.xl,
    borderWidth: 2, borderColor: colors.bgBorder, borderStyle: 'dashed',
    padding: spacing['3xl'], alignItems: 'center', marginBottom: spacing['2xl'],
  },
  uploadZoneDisabled: { opacity: 0.5 },
  uploadZoneActive: { borderColor: colors.scan, borderStyle: 'solid' },
  uploadContent: { alignItems: 'center' },
  uploadIconBg: {
    width: 80, height: 80, borderRadius: 40,
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    alignItems: 'center', justifyContent: 'center', marginBottom: spacing.lg,
  },
  uploadText: { fontFamily: 'monospace', fontSize: fontSizes.base, color: colors.textPrimary, fontWeight: '500', marginBottom: spacing.sm },
  uploadHint: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  uploadFileName: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500', marginTop: spacing.sm, marginBottom: spacing.lg },
  uploadSpeedBadge: {
    flexDirection: 'row', alignItems: 'center', gap: spacing.xs,
    marginTop: spacing.lg, paddingHorizontal: spacing.md, paddingVertical: spacing.xs,
    backgroundColor: colors.bgElevated, borderRadius: borderRadius.full,
  },
  uploadSpeedText: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  progressBar: {
    width: '100%', height: 6, backgroundColor: colors.bgElevated,
    borderRadius: borderRadius.full, overflow: 'hidden',
  },
  progressFill: { height: '100%', backgroundColor: colors.scan, borderRadius: borderRadius.full },
  progressText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.scan, marginTop: spacing.sm, fontWeight: '600' },
  infoGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: spacing.md },
  infoCard: {
    width: '47%', backgroundColor: colors.bgSurface, borderRadius: borderRadius.md,
    padding: spacing.lg, borderWidth: 1, borderColor: colors.bgBorder,
  },
  infoTitle: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: colors.textPrimary, marginTop: spacing.sm },
  infoDesc: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xs },
  pipelinePanel: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg,
    padding: spacing.lg, marginTop: spacing['2xl'],
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  pipelineTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.xs },
  pipelineFile: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, marginBottom: spacing.lg },
  pipelineStage: {
    flexDirection: 'row', alignItems: 'center', gap: spacing.sm,
    paddingVertical: spacing.md, borderBottomWidth: 1, borderBottomColor: colors.bgBorder,
  },
  pipelineDot: { width: 8, height: 8, borderRadius: 4 },
  pipelineStageContent: { flex: 1 },
  pipelineStageName: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '500' },
  pipelineStageDetail: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: 2 },
  stageStatus: { paddingHorizontal: spacing.sm, paddingVertical: 2, borderRadius: borderRadius.sm },
  stageStatusText: { fontFamily: 'monospace', fontSize: fontSizes['2xs'], fontWeight: '700' },
  pipelineBanner: {
    marginTop: spacing.lg, padding: spacing.lg, borderRadius: borderRadius.md, alignItems: 'center',
  },
  pipelineBannerText: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '700', letterSpacing: 1 },
  sectionTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.md },
  recentItem: {
    flexDirection: 'row', alignItems: 'center', backgroundColor: colors.bgSurface,
    borderRadius: borderRadius.md, padding: spacing.lg, marginBottom: spacing.sm,
    borderWidth: 1, borderColor: colors.bgBorder,
  },
  recentName: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary },
  recentMeta: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xs },
  recentStatus: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '700', letterSpacing: 0.5 },
});
