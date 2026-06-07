import { useState, useRef, useEffect, useCallback } from 'react';
import { Bot, X, Send, Shield, Trash2, RotateCcw, Copy, Check, Upload, Sparkles } from 'lucide-react';
import api from '../services/api';
import './AICopilot.css';
import html2pdf from 'html2pdf.js';
import { marked } from 'marked';

/**
 * StackDrive AI Security Copilot
 * 
 * A floating chatbot assistant that can:
 *  - Explain file scan results in plain English
 *  - Answer why files were blocked
 *  - Generate PDF security reports
 *  - Compare files by risk
 *  - Search files by name
 *  - Answer general cybersecurity questions
 * 
 * Uses the backend /api/copilot/chat endpoint which wraps
 * the Gemini API with the StackDrive system prompt context.
 */

const QUICK_ACTIONS = [
  { label: '🛡 What is StackDrive?', message: 'What is StackDrive and how does it protect my files?', icon: '🛡' },
  { label: '📊 My Dashboard', message: 'Give me a summary of my dashboard — how many files are safe and blocked?', icon: '📊' },
  { label: '🏆 Compare Files', message: 'Compare my files and rank them by risk score', icon: '🏆' },
  { label: '⚠ Recent Threats', message: 'Are there any recent threats or blocked files in my account?', icon: '⚠' },
  { label: '🧭 Recommendations', message: 'What should I do next?', icon: '🧭' },
  { label: '🔐 What is ML-KEM?', message: 'What is ML-KEM and why does StackDrive use it?', icon: '🔐' },
];

const LOADING_STAGES = [
  'Looking up your files...',
  'Running analysis...',
  'Composing response...',
];

export default function AICopilot() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [files, setFiles] = useState([]);
  const [selectedFileId, setSelectedFileId] = useState('');
  const [isDownloading, setIsDownloading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState(LOADING_STAGES[0]);
  const [copiedIdx, setCopiedIdx] = useState(null);
  const chatRef = useRef(null);
  const textareaRef = useRef(null);
  const messagesEndRef = useRef(null);
  const loadingInterval = useRef(null);

  // Fetch files when copilot opens
  useEffect(() => {
    if (isOpen) {
      api.getFiles('all').then(data => {
        if (data.files) {
          const uniqueFiles = [];
          const seenNames = new Set();
          for (const f of data.files) {
            if (!seenNames.has(f.name)) {
              seenNames.add(f.name);
              uniqueFiles.push(f);
            }
          }
          setFiles(uniqueFiles);
        }
      }).catch(err => console.error(err));
    }
  }, [isOpen]);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = '42px';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 120) + 'px';
    }
  }, [input]);

  // Cycle loading messages
  useEffect(() => {
    if (isLoading) {
      let stage = 0;
      setLoadingMsg(LOADING_STAGES[0]);
      loadingInterval.current = setInterval(() => {
        stage = Math.min(stage + 1, LOADING_STAGES.length - 1);
        setLoadingMsg(LOADING_STAGES[stage]);
      }, 2000);
    } else {
      if (loadingInterval.current) clearInterval(loadingInterval.current);
    }
    return () => { if (loadingInterval.current) clearInterval(loadingInterval.current); };
  }, [isLoading]);

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (
        chatRef.current &&
        !chatRef.current.contains(e.target) &&
        !e.target.closest('.copilot-floating-btn')
      ) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const sendMessage = useCallback(async (text) => {
    const userMessage = text.trim();
    if (!userMessage || isLoading) return;

    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setInput('');
    setIsLoading(true);

    try {
      const data = await api.sendCopilotMessage(userMessage);
      setMessages(prev => [...prev, {
        role: 'bot',
        content: data.reply || 'I couldn\'t process that request. Please try again.',
      }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'bot',
        content: `⚠ ${err.message || 'Connection error. Please check that the backend is running.'}`,
      }]);
    } finally {
      setIsLoading(false);
    }
  }, [isLoading]);

  const handleSend = () => sendMessage(input);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleQuickAction = (message) => sendMessage(message);

  const handleNewChat = async () => {
    setMessages([]);
    try { await api.clearCopilotHistory(); } catch {}
  };

  const handleCopyMessage = (text, idx) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 2000);
    });
  };

  const handleDownloadPDF = async () => {
    if (!selectedFileId) return;
    const selectedFile = files.find(f => f.id === selectedFileId);
    if (!selectedFile) return;

    setIsDownloading(true);
    try {
      const markdownText = await api.downloadCopilotReportData(selectedFileId);
      const htmlContent = marked.parse(markdownText);
      
      const container = document.createElement('div');
      container.innerHTML = `
        <div style="font-family: 'Inter', sans-serif; padding: 40px; color: #1e293b; max-width: 800px; margin: 0 auto; line-height: 1.6;">
          <div style="border-bottom: 2px solid #3b82f6; padding-bottom: 10px; margin-bottom: 20px;">
            <h1 style="color: #0f172a; font-size: 24px; margin: 0;">🛡️ StackDrive Security Report</h1>
            <p style="color: #64748b; font-size: 14px; margin: 5px 0 0 0;">Generated on ${new Date().toLocaleString()}</p>
          </div>
          <div style="font-size: 14px;">
            ${htmlContent.replace(/✅/g, '<span style="color: #10b981;">✅</span>').replace(/🚫|❌/g, '<span style="color: #ef4444;">❌</span>')}
          </div>
          <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; color: #94a3b8; font-size: 12px;">
            Powered by StackDrive Bot
          </div>
        </div>
      `;
      
      const opt = {
        margin: 10,
        filename: `${selectedFile.name}_Security_Report.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
      };

      await html2pdf().from(container).set(opt).save();
      
      setMessages(prev => [...prev, {
        role: 'bot',
        content: `✅ I have generated the PDF report for **${selectedFile.name}** and started the download!`
      }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'bot',
        content: `❌ Failed to download PDF report: ${error.message}`
      }]);
    } finally {
      setIsDownloading(false);
    }
  };

  const getFileStatusEmoji = (status) => {
    if (status === 'safe') return '✅';
    if (status === 'blocked') return '🚫';
    if (status === 'scanning') return '🔄';
    return '⏳';
  };

  const userInitial = (() => {
    try {
      const session = JSON.parse(localStorage.getItem('stackdrive_session') || '{}');
      return (session.user?.email?.[0] || 'U').toUpperCase();
    } catch {
      return 'U';
    }
  })();

  return (
    <>
      {/* Floating Button */}
      <button
        className={`copilot-floating-btn ${isOpen ? 'open' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
        aria-label="Open StackDrive Bot"
        id="copilot-toggle"
      >
        {isOpen ? <X /> : <Bot />}
        {!isOpen && <span className="copilot-ping" />}
      </button>

      {/* Chat Window */}
      {isOpen && (
        <div className="copilot-window" ref={chatRef}>
          {/* Header */}
          <div className="copilot-header">
            <div className="copilot-header-left">
              <div className="copilot-header-icon">
                <Sparkles size={14} />
              </div>
              <div className="copilot-header-info">
                <span className="copilot-header-title">StackDrive Bot</span>
                <span className="copilot-header-subtitle">
                  <span className="copilot-status-dot" />
                  AI-Powered
                </span>
              </div>
            </div>
            <div className="copilot-header-right">
              <button
                className="copilot-header-action"
                onClick={handleNewChat}
                title="New Chat"
                id="copilot-new-chat"
              >
                <RotateCcw size={14} />
              </button>
              <button
                className="copilot-header-action"
                onClick={() => { setMessages([]); }}
                title="Clear Messages"
                id="copilot-clear"
              >
                <Trash2 size={14} />
              </button>
              <button
                className="copilot-close-btn"
                onClick={() => setIsOpen(false)}
                id="copilot-close"
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Messages */}
          {messages.length === 0 ? (
            <div className="copilot-welcome">
              <div className="copilot-welcome-glow" />
              <div className="copilot-welcome-icon">
                <Shield />
              </div>
              <h3>StackDrive Bot</h3>
              <p>
                I can explain scan results, tell you why files were blocked,
                generate security reports, compare threats, and answer cybersecurity questions.
              </p>

              {files.length === 0 && (
                <div className="copilot-upload-cta">
                  <Upload size={16} />
                  <span>Upload a file first to get personalized insights</span>
                </div>
              )}

              <div className="copilot-quick-actions">
                {QUICK_ACTIONS.map((action, i) => (
                  <button
                    key={i}
                    className="copilot-quick-btn"
                    onClick={() => handleQuickAction(action.message)}
                    id={`copilot-quick-${i}`}
                  >
                    {action.label}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="copilot-messages">
              {messages.map((msg, i) => (
                <div key={i} className={`copilot-msg copilot-msg--${msg.role === 'user' ? 'user' : 'bot'}`}>
                  <div className="copilot-msg-avatar">
                    {msg.role === 'bot' ? <Bot size={16} /> : userInitial}
                  </div>
                  <div className="copilot-msg-content">
                    <div className="copilot-msg-bubble">
                      {formatMessage(msg.content)}
                    </div>
                    {msg.role === 'bot' && (
                      <button
                        className={`copilot-copy-btn ${copiedIdx === i ? 'copied' : ''}`}
                        onClick={() => handleCopyMessage(msg.content, i)}
                        title="Copy response"
                      >
                        {copiedIdx === i ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
                      </button>
                    )}
                  </div>
                </div>
              ))}

              {isLoading && (
                <div className="copilot-msg copilot-msg--bot">
                  <div className="copilot-msg-avatar"><Bot size={16} /></div>
                  <div className="copilot-msg-content">
                    <div className="copilot-msg-bubble">
                      <div className="copilot-typing">
                        <span className="copilot-typing-text">{loadingMsg}</span>
                        <div className="copilot-typing-dots">
                          <span className="copilot-typing-dot" />
                          <span className="copilot-typing-dot" />
                          <span className="copilot-typing-dot" />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>
          )}

          {/* Input */}
          <div className="copilot-input-area">
            {files.length > 0 && (
              <div className="copilot-file-selector">
                <select 
                  className="copilot-file-select"
                  value={selectedFileId} 
                  onChange={(e) => setSelectedFileId(e.target.value)}
                  id="copilot-file-dropdown"
                >
                  <option value="">Select a file for quick actions...</option>
                  {files.map(f => (
                    <option key={f.id} value={f.id}>
                      {getFileStatusEmoji(f.status)} {f.name}
                    </option>
                  ))}
                </select>
                
                {selectedFileId && (
                  <div className="copilot-file-actions">
                    <button 
                      className="copilot-quick-btn copilot-action-explain"
                      onClick={() => handleQuickAction(`Explain what ${files.find(f => f.id === selectedFileId)?.name} is`)}
                    >
                      🔍 Explain
                    </button>
                    <button 
                      className="copilot-quick-btn copilot-action-blocked"
                      onClick={() => handleQuickAction(`Why was ${files.find(f => f.id === selectedFileId)?.name} detected?`)}
                    >
                      🚫 Why Blocked?
                    </button>
                    <button 
                      className="copilot-quick-btn copilot-action-risk"
                      onClick={() => handleQuickAction(`How dangerous is ${files.find(f => f.id === selectedFileId)?.name}?`)}
                    >
                      ⚠ Risk
                    </button>
                    <button 
                      className="copilot-quick-btn copilot-action-pdf"
                      onClick={handleDownloadPDF}
                      disabled={isDownloading}
                    >
                      {isDownloading ? '⏳ Generating...' : '📄 PDF Report'}
                    </button>
                  </div>
                )}
              </div>
            )}
            
            <div className="copilot-input-row">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                rows={1}
                className="copilot-textarea"
                placeholder="Ask about your files, threats, or security..."
                disabled={isLoading}
                id="copilot-input"
              />
              <button
                className="copilot-send-btn"
                onClick={handleSend}
                disabled={!input.trim() || isLoading}
                aria-label="Send message"
                id="copilot-send"
              >
                <Send />
              </button>
            </div>

          </div>
        </div>
      )}
    </>
  );
}


/**
 * Format bot messages with basic markdown-like styling.
 * Handles **bold**, `code`, ### headings, --- hr, and line breaks.
 */
function formatMessage(text) {
  if (!text) return null;

  const lines = text.split('\n');

  return lines.map((line, lineIndex) => {
    // Heading detection
    if (line.startsWith('### ')) {
      return <h4 key={lineIndex} className="copilot-msg-h4">{processInline(line.slice(4))}</h4>;
    }
    if (line.startsWith('## ')) {
      return <h3 key={lineIndex} className="copilot-msg-h3">{processInline(line.slice(3))}</h3>;
    }
    if (line.startsWith('# ')) {
      return <h2 key={lineIndex} className="copilot-msg-h2">{processInline(line.slice(2))}</h2>;
    }
    if (line.trim() === '---') {
      return <hr key={lineIndex} className="copilot-msg-hr" />;
    }

    const parts = processInline(line);

    return (
      <span key={lineIndex}>
        {parts}
        {lineIndex < lines.length - 1 && <br />}
      </span>
    );
  });
}

function processInline(line) {
  const parts = [];
  let remaining = line;
  let key = 0;

  while (remaining.length > 0) {
    const boldMatch = remaining.match(/\*\*(.+?)\*\*/);
    const codeMatch = remaining.match(/`([^`]+)`/);

    let earliestMatch = null;
    let earliestIndex = remaining.length;
    let matchType = null;

    if (boldMatch && boldMatch.index < earliestIndex) {
      earliestMatch = boldMatch;
      earliestIndex = boldMatch.index;
      matchType = 'bold';
    }
    if (codeMatch && codeMatch.index < earliestIndex) {
      earliestMatch = codeMatch;
      earliestIndex = codeMatch.index;
      matchType = 'code';
    }

    if (!earliestMatch) {
      parts.push(<span key={key++}>{remaining}</span>);
      break;
    }

    if (earliestIndex > 0) {
      parts.push(<span key={key++}>{remaining.substring(0, earliestIndex)}</span>);
    }

    if (matchType === 'bold') {
      parts.push(<strong key={key++}>{earliestMatch[1]}</strong>);
    } else if (matchType === 'code') {
      parts.push(<code key={key++}>{earliestMatch[1]}</code>);
    }

    remaining = remaining.substring(earliestIndex + earliestMatch[0].length);
  }

  return parts;
}
