import React, { useState, useEffect, useCallback } from 'react';
import { StatusBar } from 'expo-status-bar';
import {
  View, Text, StyleSheet, TouchableOpacity, SafeAreaView, Platform,
  ActivityIndicator, StatusBar as RNStatusBar,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { AuthProvider, useAuth } from './src/context/AuthContext';
import { ToastProvider } from './src/context/ToastContext';
import { colors, spacing, borderRadius, fontSizes } from './src/theme/colors';
import api from './src/services/api';

// Screens
import LoginScreen from './src/screens/LoginScreen';
import SignupScreen from './src/screens/SignupScreen';
import ForgotPasswordScreen from './src/screens/ForgotPasswordScreen';
import DashboardScreen from './src/screens/DashboardScreen';
import UploadScreen from './src/screens/UploadScreen';
import FileHistoryScreen from './src/screens/FileHistoryScreen';
import SharedFilesScreen from './src/screens/SharedFilesScreen';
import SecurityScreen from './src/screens/SecurityScreen';
import SettingsScreen from './src/screens/SettingsScreen';
import LogoutScreen from './src/screens/LogoutScreen';
import NotificationPanel from './src/components/NotificationPanel';
import AICopilot, { RobotAvatar } from './src/components/AICopilot';

// Tab navigation items
const tabs = [
  { key: 'overview', label: 'Overview', icon: 'stats-chart' },
  { key: 'upload', label: 'Upload', icon: 'cloud-upload' },
  { key: 'history', label: 'Files', icon: 'folder-open' },
  { key: 'shares', label: 'Shares', icon: 'share-social' },
  { key: 'security', label: 'Security', icon: 'shield-checkmark' },
];

// Header component
function AppHeader({ title, subtitle, activeTab, onSettingsPress, onNotificationsPress, healthStatus, onCheckHealth }: any) {
  const getHealthIcon = () => {
    if (!healthStatus) return null;
    if (healthStatus.status === 'checking') {
      return <ActivityIndicator size="small" color={colors.accent} />;
    }
    if (healthStatus.status === 'connected' && healthStatus.database === 'connected') {
      return (
        <TouchableOpacity onPress={onCheckHealth} style={headerStyles.healthIndicator} activeOpacity={0.7}>
          <View style={[headerStyles.dot, { backgroundColor: colors.safe }]} />
          <Text style={[headerStyles.healthLabel, { color: colors.safe }]}>Gateway Online</Text>
        </TouchableOpacity>
      );
    }
    return (
      <TouchableOpacity onPress={onCheckHealth} style={headerStyles.healthIndicator} activeOpacity={0.7}>
        <View style={[headerStyles.dot, { backgroundColor: colors.threat }]} />
        <Text style={[headerStyles.healthLabel, { color: colors.threat }]}>Gateway Error</Text>
      </TouchableOpacity>
    );
  };

  return (
    <View style={headerStyles.container}>
      <View style={{ flex: 1 }}>
        <Text style={headerStyles.title}>{title}</Text>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6, marginTop: 2 }}>
          {getHealthIcon()}
          {subtitle && <Text style={headerStyles.subtitle}>| {subtitle}</Text>}
        </View>
      </View>
      <View style={headerStyles.right}>
        <TouchableOpacity
          style={headerStyles.iconBtn}
          onPress={onNotificationsPress}
          activeOpacity={0.7}
        >
          <Ionicons name="notifications-outline" size={22} color={colors.textSecondary} />
        </TouchableOpacity>
        <TouchableOpacity
          style={headerStyles.iconBtn}
          onPress={onSettingsPress}
          activeOpacity={0.7}
        >
          <Ionicons name="settings-outline" size={22} color={colors.textSecondary} />
        </TouchableOpacity>
      </View>
    </View>
  );
}

const headerStyles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    backgroundColor: colors.bgBase,
    borderBottomWidth: 1,
    borderBottomColor: colors.bgBorder,
  },
  title: {
    fontFamily: 'monospace',
    fontSize: fontSizes.lg,
    fontWeight: '600',
    color: colors.textPrimary,
  },
  subtitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
  },
  right: {
    flexDirection: 'row',
    gap: spacing.xs,
  },
  iconBtn: {
    width: 40,
    height: 40,
    borderRadius: borderRadius.md,
    backgroundColor: colors.bgSurface,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: colors.bgBorder,
  },
  healthIndicator: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  healthLabel: {
    fontFamily: 'monospace',
    fontSize: fontSizes['2xs'],
    fontWeight: '600',
  },
});

// Tab Bar component
function TabBar({ activeTab, onTabPress }: { activeTab: string; onTabPress: (key: string) => void }) {
  return (
    <View style={tabStyles.container}>
      {tabs.map((tab) => {
        const isActive = activeTab === tab.key;
        return (
          <TouchableOpacity
            key={tab.key}
            style={[tabStyles.tab, isActive && tabStyles.tabActive]}
            onPress={() => onTabPress(tab.key)}
            activeOpacity={0.7}
          >
            <Ionicons
              name={(isActive ? tab.icon : `${tab.icon}-outline`) as any}
              size={22}
              color={isActive ? colors.accent : colors.textMuted}
            />
            <Text style={[tabStyles.label, isActive && tabStyles.labelActive]}>
              {tab.label}
            </Text>
            {isActive && <View style={tabStyles.activeIndicator} />}
          </TouchableOpacity>
        );
      })}
    </View>
  );
}

const tabStyles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    backgroundColor: colors.bgSurface,
    borderTopWidth: 1,
    borderTopColor: colors.bgBorder,
    paddingBottom: Platform.OS === 'ios' ? 20 : 8,
    paddingTop: spacing.sm,
  },
  tab: {
    flex: 1,
    alignItems: 'center',
    paddingVertical: spacing.sm,
    position: 'relative',
  },
  tabActive: {},
  label: {
    fontFamily: 'monospace',
    fontSize: fontSizes['2xs'],
    color: colors.textMuted,
    marginTop: 4,
  },
  labelActive: {
    color: colors.accent,
    fontWeight: '600',
  },
  activeIndicator: {
    position: 'absolute',
    top: -1,
    width: 24,
    height: 2,
    backgroundColor: colors.accent,
    borderRadius: 1,
  },
});

// Page titles
const pageTitles: Record<string, { title: string; subtitle?: string }> = {
  overview: { title: 'Overview', subtitle: 'Real-time security dashboard' },
  upload: { title: 'Upload', subtitle: 'Secure file ingestion' },
  history: { title: 'File History', subtitle: 'All processed files' },
  shares: { title: 'Shared Files', subtitle: 'External access management' },
  security: { title: 'Security', subtitle: 'Pipeline monitoring' },
  settings: { title: 'Settings', subtitle: 'Account & AWS management' },
};

function MainApp() {
  const { user, login, loading, isLoggingOut } = useAuth();
  const [authScreen, setAuthScreen] = useState<'login' | 'signup' | 'forgot'>('login');
  const [activeTab, setActiveTab] = useState('overview');
  const [showSettings, setShowSettings] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showCopilot, setShowCopilot] = useState(false);

  const [healthStatus, setHealthStatus] = useState<{
    status: 'checking' | 'connected' | 'error';
    database: 'connected' | 'disconnected' | 'unknown';
    pqc: string;
    message: string;
  }>({
    status: 'checking',
    database: 'unknown',
    pqc: 'unknown',
    message: '',
  });

  const checkGatewayHealth = useCallback(async () => {
    try {
      const apiBase = await api.getApiBase();
      const res = await api.testConnection(apiBase);
      if (res.success) {
        setHealthStatus({
          status: 'connected',
          database: res.database === 'connected' ? 'connected' : 'disconnected',
          pqc: res.pqc || 'unknown',
          message: res.database !== 'connected' ? 'Database connection error on server.' : '',
        });
      } else {
        // Self-healing: if custom URL fails, test default resolved URL
        const defaultApiBase = api.getApiBaseDefault();
        const customApiBase = await api.getCustomApiBase();
        
        if (customApiBase && customApiBase !== defaultApiBase) {
          const defaultRes = await api.testConnection(defaultApiBase);
          if (defaultRes.success) {
            await api.setCustomApiBase(null); // Clear stale custom URL
            setHealthStatus({
              status: 'connected',
              database: defaultRes.database === 'connected' ? 'connected' : 'disconnected',
              pqc: defaultRes.pqc || 'unknown',
              message: 'Stale custom gateway URL cleared. Switched back to default.',
            });
            return;
          }
        }

        setHealthStatus({
          status: 'error',
          database: 'unknown',
          pqc: 'unknown',
          message: res.error || 'Cannot reach Linux server',
        });
      }
    } catch (err: any) {
      setHealthStatus({
        status: 'error',
        database: 'unknown',
        pqc: 'unknown',
        message: err.message || 'Network request failed',
      });
    }
  }, []);

  useEffect(() => {
    checkGatewayHealth();
    const interval = setInterval(checkGatewayHealth, 15000); // Check every 15s
    return () => clearInterval(interval);
  }, [checkGatewayHealth]);

  if (loading) {
    return (
      <View style={styles.loadingScreen}>
        <StatusBar style="light" />
        <View style={styles.loadingContent}>
          <Ionicons name="shield-checkmark" size={48} color={colors.accent} />
          <Text style={styles.loadingText}>StackDrive</Text>
          <ActivityIndicator size="small" color={colors.accent} style={{ marginTop: spacing.xl }} />
        </View>
      </View>
    );
  }

  if (isLoggingOut) {
    return <LogoutScreen />;
  }

  // Auth screens
  if (!user) {
    return (
      <View style={styles.authContainer}>
        <StatusBar style="light" />
        {healthStatus.status === 'error' && (
          <View style={styles.topWarningBanner}>
            <Ionicons name="alert-circle" size={16} color="#fff" />
            <Text style={styles.warningBannerText} numberOfLines={1}>
              Offline: {healthStatus.message}
            </Text>
            <TouchableOpacity onPress={checkGatewayHealth} style={styles.retryBtn}>
              <Text style={styles.retryBtnText}>Retry</Text>
            </TouchableOpacity>
          </View>
        )}
        {healthStatus.status === 'connected' && healthStatus.database === 'disconnected' && (
          <View style={[styles.topWarningBanner, { backgroundColor: colors.threat }]}>
            <Ionicons name="warning" size={16} color="#fff" />
            <Text style={styles.warningBannerText} numberOfLines={1}>
              Linux Database Offline: Check SQLite database.
            </Text>
            <TouchableOpacity onPress={checkGatewayHealth} style={styles.retryBtn}>
              <Text style={styles.retryBtnText}>Retry</Text>
            </TouchableOpacity>
          </View>
        )}
        {authScreen === 'login' && (
          <LoginScreen
            onLogin={login}
            onNavigateSignup={() => setAuthScreen('signup')}
            onNavigateForgot={() => setAuthScreen('forgot')}
          />
        )}
        {authScreen === 'signup' && (
          <SignupScreen
            onLogin={login}
            onNavigateLogin={() => setAuthScreen('login')}
          />
        )}
        {authScreen === 'forgot' && (
          <ForgotPasswordScreen
            onNavigateLogin={() => setAuthScreen('login')}
          />
        )}
      </View>
    );
  }

  // Main App
  const currentPage = showSettings ? 'settings' : activeTab;
  const pageInfo = pageTitles[currentPage] || { title: 'StackDrive' };

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar style="light" />
      <AppHeader
        title={pageInfo.title}
        subtitle={pageInfo.subtitle}
        activeTab={currentPage}
        onSettingsPress={() => setShowSettings(!showSettings)}
        onNotificationsPress={() => setShowNotifications(true)}
        healthStatus={healthStatus}
        onCheckHealth={checkGatewayHealth}
      />
      {healthStatus.status === 'error' && (
        <View style={styles.topWarningBanner}>
          <Ionicons name="alert-circle" size={16} color="#fff" />
          <Text style={styles.warningBannerText} numberOfLines={1}>
            Offline: {healthStatus.message}
          </Text>
          <TouchableOpacity onPress={checkGatewayHealth} style={styles.retryBtn}>
            <Text style={styles.retryBtnText}>Retry</Text>
          </TouchableOpacity>
        </View>
      )}
      {healthStatus.status === 'connected' && healthStatus.database === 'disconnected' && (
        <View style={[styles.topWarningBanner, { backgroundColor: colors.threat }]}>
          <Ionicons name="warning" size={16} color="#fff" />
          <Text style={styles.warningBannerText} numberOfLines={1}>
            Linux Database Offline: Check SQLite database.
          </Text>
          <TouchableOpacity onPress={checkGatewayHealth} style={styles.retryBtn}>
            <Text style={styles.retryBtnText}>Retry</Text>
          </TouchableOpacity>
        </View>
      )}
      <View style={styles.screenContainer}>
        {showSettings ? (
          <SettingsScreen />
        ) : (
          <>
            <View style={[styles.tabContent, activeTab === 'overview' && styles.activeTab]}>
              <DashboardScreen />
            </View>
            <View style={[styles.tabContent, activeTab === 'upload' && styles.activeTab]}>
              <UploadScreen />
            </View>
            <View style={[styles.tabContent, activeTab === 'history' && styles.activeTab]}>
              <FileHistoryScreen />
            </View>
            <View style={[styles.tabContent, activeTab === 'shares' && styles.activeTab]}>
              <SharedFilesScreen />
            </View>
            <View style={[styles.tabContent, activeTab === 'security' && styles.activeTab]}>
              <SecurityScreen />
            </View>
          </>
        )}
      </View>
      
      {/* Floating Chatbot Button */}
      {!showSettings && activeTab === 'upload' && (
        <TouchableOpacity
          style={styles.fab}
          onPress={() => setShowCopilot(true)}
          activeOpacity={0.8}
        >
          <RobotAvatar size={38} glow />
        </TouchableOpacity>
      )}

      {/* Notification Panel */}
      <NotificationPanel
        visible={showNotifications}
        onClose={() => setShowNotifications(false)}
      />

      {/* AI Copilot Panel */}
      <AICopilot
        visible={showCopilot}
        onClose={() => setShowCopilot(false)}
      />

      {!showSettings && (
        <TabBar
          activeTab={activeTab}
          onTabPress={(key) => {
            setShowSettings(false);
            setActiveTab(key);
          }}
        />
      )}
      {showSettings && (
        <View style={tabStyles.container}>
          <TouchableOpacity
            style={{ flex: 1, alignItems: 'center', paddingVertical: spacing.sm }}
            onPress={() => setShowSettings(false)}
          >
            <Ionicons name="arrow-back" size={22} color={colors.accent} />
            <Text style={[tabStyles.label, tabStyles.labelActive]}>Back</Text>
          </TouchableOpacity>
        </View>
      )}
    </SafeAreaView>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <MainApp />
      </AuthProvider>
    </ToastProvider>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: colors.bgBase,
    paddingTop: Platform.OS === 'android' ? (RNStatusBar.currentHeight || 0) : 0,
  },
  authContainer: {
    flex: 1,
    backgroundColor: colors.bgDeep,
  },
  screenContainer: {
    flex: 1,
  },
  tabContent: {
    display: 'none',
    flex: 1,
  },
  activeTab: {
    display: 'flex',
  },
  loadingScreen: {
    flex: 1,
    backgroundColor: colors.bgDeep,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingContent: {
    alignItems: 'center',
  },
  loadingText: {
    fontFamily: 'monospace',
    fontSize: fontSizes['2xl'],
    fontWeight: '700',
    color: colors.textPrimary,
    marginTop: spacing.lg,
  },
  fab: {
    position: 'absolute',
    bottom: 80,
    right: 20,
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: '#0d1527',
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#06b6d4',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 8,
    borderWidth: 1.5,
    borderColor: '#06b6d4',
  },
  topWarningBanner: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#ef4444',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    gap: spacing.sm,
  },
  warningBannerText: {
    flex: 1,
    color: '#fff',
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
  },
  retryBtn: {
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    paddingHorizontal: spacing.sm,
    paddingVertical: 4,
    borderRadius: borderRadius.sm,
  },
  retryBtnText: {
    color: '#fff',
    fontFamily: 'monospace',
    fontSize: fontSizes['2xs'],
    fontWeight: '600',
  },
});
