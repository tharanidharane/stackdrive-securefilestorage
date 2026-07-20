import React, { useState, useEffect } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity, TextInput,
  ActivityIndicator, Alert, Platform, KeyboardAvoidingView,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

export default function SettingsScreen() {
  const { user, updateUser, logout } = useAuth();
  const { addToast } = useToast();
  const [awsConnected, setAwsConnected] = useState(user?.aws_connected || false);
  const [awsDetails, setAwsDetails] = useState<any>({});
  const [connecting, setConnecting] = useState(false);
  const [provisioning, setProvisioning] = useState(false);
  const [awsForm, setAwsForm] = useState({ access_key: '', secret_key: '', region: 'ap-south-1' });

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const data = await api.getAwsStatus();
        setAwsConnected(data.connected);
        setAwsDetails(data);
      } catch { /* ignore */ }
    };
    fetchStatus();
  }, []);

  const handleConnect = async () => {
    if (!awsForm.access_key || !awsForm.secret_key) {
      addToast('Access Key and Secret Key are required', 'error');
      return;
    }
    setConnecting(true);
    setProvisioning(true);
    try {
      const data = await api.connectAws(awsForm);
      setProvisioning(false);
      setAwsConnected(true);
      setAwsDetails({
        connected: true,
        account_id: data.user.aws_account_id,
        region: data.user.aws_region,
        quarantine_bucket: data.user.quarantine_bucket,
        secure_bucket: data.user.secure_bucket,
        kms_key_arn: data.user.kms_key_arn,
      });
      updateUser(data.user);
      addToast('AWS environment provisioned successfully!', 'success');
    } catch (err: any) {
      setProvisioning(false);
      setConnecting(false);
      addToast(err.message || 'Failed to provision AWS resources', 'error');
    }
  };

  const handleDisconnect = () => {
    Alert.alert('Reconnect AWS?', 'This will revoke your current AWS credentials.', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Disconnect', style: 'destructive',
        onPress: async () => {
          try {
            const data = await api.disconnectAws();
            setAwsConnected(false);
            setAwsDetails({});
            updateUser(data.user);
            addToast('AWS disconnected', 'warning');
          } catch (err: any) {
            addToast(err.message || 'Failed to disconnect', 'error');
          }
        },
      },
    ]);
  };

  const handleLogout = () => {
    Alert.alert('Log Out', 'Are you sure you want to log out?', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Log Out', style: 'destructive', onPress: () => logout() },
    ]);
  };

  if (provisioning) {
    return (
      <View style={styles.provisionOverlay}>
        <View style={styles.provisionCard}>
          <View style={styles.provisionSpinner}>
            <Ionicons name="cloud" size={32} color={colors.accent} />
          </View>
          <Text style={styles.provisionTitle}>Setting Up AWS Resources</Text>
          <Text style={styles.provisionSub}>Auto-provisioning your secure infrastructure...</Text>
          <ActivityIndicator size="large" color={colors.accent} style={{ marginTop: spacing['2xl'] }} />
          <Text style={styles.provisionHint}>This usually takes 15-30 seconds.</Text>
        </View>
      </View>
    );
  }

  const regions = [
    { value: 'us-east-1', label: 'us-east-1 (N. Virginia)' },
    { value: 'us-east-2', label: 'us-east-2 (Ohio)' },
    { value: 'us-west-2', label: 'us-west-2 (Oregon)' },
    { value: 'eu-west-1', label: 'eu-west-1 (Ireland)' },
    { value: 'ap-south-1', label: 'ap-south-1 (Mumbai)' },
  ];

  return (
    <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView style={styles.container} contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
        <Text style={styles.pageTitle}>Settings</Text>
        <Text style={styles.pageDesc}>Manage your account and AWS connection</Text>

        {/* AWS Connection */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Ionicons name="cloud" size={18} color={colors.accent} />
            <Text style={styles.sectionTitle}>AWS Connection</Text>
          </View>

          {awsConnected ? (
            <View style={styles.awsCard}>
              <View style={styles.awsStatusRow}>
                <Ionicons name="checkmark-circle" size={20} color={colors.safe} />
                <Text style={[styles.awsStatusText, { color: colors.safe }]}>Connected</Text>
              </View>

              <View style={styles.awsDetailRow}>
                <Text style={styles.awsLabel}>Account ID</Text>
                <Text style={styles.awsValue}>
                  {awsDetails.account_id ? `•••• •••• ${awsDetails.account_id.slice(-4)}` : '•••• ••••'}
                </Text>
              </View>
              <View style={styles.awsDetailRow}>
                <Text style={styles.awsLabel}>Region</Text>
                <Text style={styles.awsValue}>{awsDetails.region || 'ap-south-1'}</Text>
              </View>
              <View style={styles.awsDetailRow}>
                <Text style={styles.awsLabel}>Quarantine</Text>
                <Text style={styles.awsValue}>{awsDetails.quarantine_bucket || 'stackdrive-quarantine'}</Text>
              </View>
              <View style={styles.awsDetailRow}>
                <Text style={styles.awsLabel}>Secure</Text>
                <Text style={styles.awsValue}>{awsDetails.secure_bucket || 'stackdrive-secure'}</Text>
              </View>
              <View style={styles.awsDetailRow}>
                <Text style={styles.awsLabel}>Credentials</Text>
                <Text style={[styles.awsValue, { color: colors.safe }]}>STS Token (Active)</Text>
              </View>

              <TouchableOpacity style={styles.reconnectBtn} onPress={handleDisconnect}>
                <Ionicons name="refresh" size={14} color={colors.textPrimary} />
                <Text style={styles.reconnectBtnText}>Reconnect AWS</Text>
              </TouchableOpacity>
            </View>
          ) : (
            <View style={styles.awsForm}>
              <Text style={styles.awsFormDesc}>
                Provide your AWS credentials. StackDrive will auto-provision S3 buckets and a KMS Key.
              </Text>

              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>ACCESS KEY ID</Text>
                <TextInput
                  style={styles.input}
                  placeholder="AKIAIOSFODNN7EXAMPLE"
                  placeholderTextColor={colors.textMuted}
                  value={awsForm.access_key}
                  onChangeText={(t) => setAwsForm({ ...awsForm, access_key: t })}
                  autoCapitalize="none"
                  autoCorrect={false}
                />
              </View>

              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>SECRET ACCESS KEY</Text>
                <TextInput
                  style={styles.input}
                  placeholder="wJalrXUtnFEMI/K7MDENG/..."
                  placeholderTextColor={colors.textMuted}
                  value={awsForm.secret_key}
                  onChangeText={(t) => setAwsForm({ ...awsForm, secret_key: t })}
                  secureTextEntry
                  autoCapitalize="none"
                  autoCorrect={false}
                />
              </View>

              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>REGION</Text>
                <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.regionScroll}>
                  {regions.map(r => (
                    <TouchableOpacity
                      key={r.value}
                      style={[styles.regionChip, awsForm.region === r.value && styles.regionChipActive]}
                      onPress={() => setAwsForm({ ...awsForm, region: r.value })}
                    >
                      <Text style={[styles.regionChipText, awsForm.region === r.value && styles.regionChipTextActive]}>
                        {r.value}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </ScrollView>
              </View>

              <TouchableOpacity
                style={[styles.primaryBtn, connecting && styles.btnDisabled]}
                onPress={handleConnect}
                disabled={connecting}
              >
                {connecting ? <ActivityIndicator size="small" color="#fff" /> : <Ionicons name="cloud" size={16} color="#fff" />}
                <Text style={styles.primaryBtnText}>
                  {connecting ? 'Provisioning...' : 'Provision AWS Account'}
                </Text>
              </TouchableOpacity>
            </View>
          )}
        </View>

        {/* User Profile */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Ionicons name="person" size={18} color={colors.accent} />
            <Text style={styles.sectionTitle}>User Profile</Text>
          </View>
          <View style={styles.profileCard}>
            <View style={styles.profileRow}>
              <Ionicons name="mail" size={16} color={colors.textMuted} />
              <View>
                <Text style={styles.profileLabel}>Email</Text>
                <Text style={styles.profileValue}>{user?.email || 'user@stackdrive.io'}</Text>
              </View>
            </View>
            <View style={styles.profileRow}>
              <Ionicons name="calendar" size={16} color={colors.textMuted} />
              <View>
                <Text style={styles.profileLabel}>Account Created</Text>
                <Text style={styles.profileValue}>
                  {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                </Text>
              </View>
            </View>
            <View style={styles.profileRow}>
              <Ionicons name="key" size={16} color={colors.textMuted} />
              <View>
                <Text style={styles.profileLabel}>User ID</Text>
                <Text style={[styles.profileValue, { fontSize: fontSizes.xs }]}>{user?.id || 'N/A'}</Text>
              </View>
            </View>
          </View>
        </View>

        {/* Logout */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Ionicons name="shield" size={18} color={colors.accent} />
            <Text style={styles.sectionTitle}>Account</Text>
          </View>
          <TouchableOpacity style={styles.logoutBtn} onPress={handleLogout}>
            <Ionicons name="log-out" size={16} color={colors.threat} />
            <Text style={styles.logoutBtnText}>Log Out</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgBase },
  content: { padding: spacing.lg, paddingBottom: spacing['4xl'] },
  pageTitle: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.sm },
  pageDesc: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, marginBottom: spacing['2xl'] },
  section: { marginBottom: spacing['2xl'] },
  sectionHeader: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm, marginBottom: spacing.lg },
  sectionTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary },
  awsCard: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg,
    padding: spacing.xl, borderWidth: 1, borderColor: colors.bgBorder,
  },
  awsStatusRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm, marginBottom: spacing.xl },
  awsStatusText: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600' },
  awsDetailRow: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingVertical: spacing.sm, borderBottomWidth: 1, borderBottomColor: colors.bgBorder,
  },
  awsLabel: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  awsValue: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textPrimary },
  reconnectBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.bgElevated, borderWidth: 1, borderColor: colors.bgBorder,
    paddingVertical: spacing.md, borderRadius: borderRadius.md, marginTop: spacing.xl,
  },
  reconnectBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary, fontWeight: '600' },
  awsForm: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg,
    padding: spacing.xl, borderWidth: 1, borderColor: colors.bgBorder,
  },
  awsFormDesc: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, lineHeight: 22, marginBottom: spacing.xl },
  inputGroup: { marginBottom: spacing.lg },
  inputLabel: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600', color: colors.textSecondary, letterSpacing: 0.5, marginBottom: spacing.sm },
  input: {
    backgroundColor: colors.bgElevated, borderRadius: borderRadius.md,
    borderWidth: 1, borderColor: colors.bgBorder,
    paddingHorizontal: spacing.md, paddingVertical: Platform.OS === 'ios' ? spacing.md : spacing.sm,
    color: colors.textPrimary, fontFamily: 'monospace', fontSize: fontSizes.sm,
  },
  regionScroll: { marginBottom: spacing.sm },
  regionChip: {
    paddingHorizontal: spacing.md, paddingVertical: spacing.sm,
    borderRadius: borderRadius.full, backgroundColor: colors.bgElevated,
    borderWidth: 1, borderColor: colors.bgBorder, marginRight: spacing.sm,
  },
  regionChipActive: { backgroundColor: colors.accent, borderColor: colors.accent },
  regionChipText: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  regionChipTextActive: { color: '#fff', fontWeight: '600' },
  primaryBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.accent, borderRadius: borderRadius.md, paddingVertical: spacing.lg,
  },
  btnDisabled: { opacity: 0.6 },
  primaryBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: '#fff', textTransform: 'uppercase', letterSpacing: 0.5 },
  profileCard: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg,
    padding: spacing.xl, borderWidth: 1, borderColor: colors.bgBorder,
  },
  profileRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.md, paddingVertical: spacing.md },
  profileLabel: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted },
  profileValue: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textPrimary },
  logoutBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.threatBg, borderWidth: 1, borderColor: colors.threatBorder,
    paddingVertical: spacing.lg, borderRadius: borderRadius.md,
  },
  logoutBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: colors.threat, textTransform: 'uppercase', letterSpacing: 0.5 },
  provisionOverlay: {
    flex: 1, backgroundColor: colors.bgBase, justifyContent: 'center', alignItems: 'center', padding: spacing['3xl'],
  },
  provisionCard: { alignItems: 'center' },
  provisionSpinner: {
    width: 80, height: 80, borderRadius: 40,
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    alignItems: 'center', justifyContent: 'center', marginBottom: spacing['2xl'],
  },
  provisionTitle: { fontFamily: 'monospace', fontSize: fontSizes.lg, fontWeight: '600', color: colors.textPrimary, textAlign: 'center' },
  provisionSub: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, textAlign: 'center', marginTop: spacing.sm },
  provisionHint: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.textMuted, marginTop: spacing.xl },
});
