import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquare, X, Maximize2, Minimize2, Send, Sparkles, Bot, User, ChevronDown, Mic, MicOff, Volume2, VolumeX, FolderOpen, Save, Trash2 } from 'lucide-react';
import { apiFetch } from '../lib/api.js';
import { useVoice } from '../lib/useVoice.js';

const HOT_QUESTIONS = [
  { label: '🛡️ Security Overview', prompt: 'Give me a high-level security overview of my project. What are the most critical areas to focus on?' },
  { label: '🔧 Best Practices', prompt: 'What security best practices should I follow for my web application?' },
  { label: '📊 Risk Assessment', prompt: 'Help me understand common risk assessment methodologies for penetration testing.' },
  { label: '🕵️ OWASP Top 10', prompt: 'Explain the current OWASP Top 10 vulnerabilities and how to mitigate them.' },
  { label: '🔐 Hardening Tips', prompt: 'What are the essential server hardening steps I should take?' },
  { label: '📋 Compliance', prompt: 'What security compliance frameworks should I be aware of (e.g., PCI-DSS, SOC2, ISO 27001)?' },
];

function TypingIndicator() {
  return (
    <div className="ai-chat-typing flex items-center gap-1 px-4 py-3">
      <Bot className="w-4 h-4 text-white/60 mr-2 flex-shrink-0" />
      <span className="typing-dot" />
      <span className="typing-dot" style={{ animationDelay: '0.15s' }} />
      <span className="typing-dot" style={{ animationDelay: '0.3s' }} />
    </div>
  );
}

export default function AIChatWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [showHotQuestions, setShowHotQuestions] = useState(true);
  const [speakingMsgId, setSpeakingMsgId] = useState(null);
  const [autoSpeak, setAutoSpeak] = useState(false);
  const [workspacePath, setWorkspacePath] = useState('');
  const [attachedFiles, setAttachedFiles] = useState([]);
  const [fileBusyPath, setFileBusyPath] = useState('');
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const scrollContainerRef = useRef(null);

  const voice = useVoice();

  // When STT produces a transcript, update the input field
  useEffect(() => {
    if (voice.transcript) {
      setInput(voice.transcript);
    }
  }, [voice.transcript]);

  // Track which message is being spoken
  useEffect(() => {
    if (!voice.isSpeaking) {
      setSpeakingMsgId(null);
    }
  }, [voice.isSpeaking]);

  // Auto-speak new AI responses when autoSpeak is on
  useEffect(() => {
    if (!autoSpeak || messages.length === 0) return;
    const lastMsg = messages[messages.length - 1];
    if (lastMsg.role === 'assistant' && !lastMsg.isError) {
      voice.speak(lastMsg.content);
      setSpeakingMsgId(lastMsg.id);
    }
  }, [messages, autoSpeak]); // eslint-disable-line react-hooks/exhaustive-deps

  function handleMicToggle() {
    if (voice.isListening) {
      voice.stopListening();
      // Auto-send if we have a transcript
      if (voice.transcript.trim()) {
        setTimeout(() => {
          sendMessage(voice.transcript.trim());
          voice.setTranscript('');
        }, 300);
      }
    } else {
      setInput('');
      voice.setTranscript('');
      voice.startListening();
    }
  }

  function handleSpeakMessage(msg) {
    if (speakingMsgId === msg.id) {
      voice.stopSpeaking();
      setSpeakingMsgId(null);
    } else {
      voice.speak(msg.content);
      setSpeakingMsgId(msg.id);
    }
  }

  function extractSuggestedFileContent(text) {
    if (!text) return '';

    const fenced = text.match(/```(?:[\w-]+)?\n([\s\S]*?)```/);
    if (fenced?.[1]) {
      return fenced[1].trim();
    }

    return text.trim();
  }

  async function loadWorkspaceFile() {
    const targetPath = workspacePath.trim();
    if (!targetPath || loading) return;

    setFileBusyPath(targetPath);
    try {
      const res = await apiFetch(`/api/ai/files?path=${encodeURIComponent(targetPath)}`);
      const fileRecord = {
        path: res.path,
        content: res.content,
        size: res.size,
        modifiedAt: res.modifiedAt,
      };

      setAttachedFiles((prev) => [
        ...prev.filter((item) => item.path !== res.path),
        fileRecord,
      ]);
      setWorkspacePath('');
    } catch (err) {
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: `⚠️ ${err.message || 'Failed to load file.'}`,
        id: Date.now() + 1,
        isError: true,
      }]);
    } finally {
      setFileBusyPath('');
    }
  }

  function removeAttachment(path) {
    setAttachedFiles((prev) => prev.filter((item) => item.path !== path));
  }

  async function applyAssistantToFile(file) {
    const lastAssistant = [...messages].reverse().find((msg) => msg.role === 'assistant' && !msg.isError);
    if (!lastAssistant) {
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: '⚠️ Generate an AI response first, then apply it to the file.',
        id: Date.now() + 1,
        isError: true,
      }]);
      return;
    }

    const nextContent = extractSuggestedFileContent(lastAssistant.content);
    if (!nextContent) {
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: `⚠️ The latest AI response did not contain usable file content for ${file.path}.`,
        id: Date.now() + 1,
        isError: true,
      }]);
      return;
    }

    const ok = window.confirm(`Overwrite ${file.path} with the latest AI response?`);
    if (!ok) return;

    setFileBusyPath(file.path);
    try {
      const res = await apiFetch('/api/ai/files', {
        method: 'PUT',
        body: {
          path: file.path,
          content: nextContent,
        },
      });

      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: `✅ Saved updated content to ${res.path}`,
        id: Date.now() + 1,
      }]);
    } catch (err) {
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: `⚠️ ${err.message || `Failed to save ${file.path}`}`,
        id: Date.now() + 1,
        isError: true,
      }]);
    } finally {
      setFileBusyPath('');
    }
  }

  const scrollToBottom = useCallback(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading, scrollToBottom]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 300);
    }
  }, [isOpen]);

  async function sendMessage(text) {
    const prompt = text.trim() || (attachedFiles.length > 0 ? 'Please read the attached file context and help me update it.' : '');
    if (!prompt || loading) return;
    
    const userMsg = { role: 'user', content: prompt, id: Date.now() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setShowHotQuestions(false);
    setLoading(true);

    try {
      const res = await apiFetch('/api/ai/chat', {
        method: 'POST',
        body: {
          message: prompt,
          history: messages.slice(-10).map(m => ({ role: m.role, content: m.content })),
          attachments: attachedFiles.map(({ path, content, size, modifiedAt }) => ({
            path,
            content,
            size,
            modifiedAt,
          })),
        },
      });
      
      const aiMsg = {
        role: 'assistant',
        content: res.response || 'I apologize, but I was unable to generate a response. Please try again.',
        id: Date.now() + 1,
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      const errorMsg = {
        role: 'assistant',
        content: `⚠️ ${err.message || 'Failed to get AI response. Please ensure the AI service is configured.'}`,
        id: Date.now() + 1,
        isError: true,
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  }

  function clearChat() {
    setMessages([]);
    setShowHotQuestions(true);
    setAttachedFiles([]);
    setWorkspacePath('');
  }

  // Fab button animation variants
  const fabVariants = {
    idle: { scale: 1 },
    hover: { scale: 1.1, boxShadow: '0 0 30px rgba(255,255,255,0.3)' },
    tap: { scale: 0.9 },
  };

  // Panel animation variants
  const panelVariants = {
    hidden: { opacity: 0, y: 30, scale: 0.9 },
    visible: {
      opacity: 1, y: 0, scale: 1,
      transition: { type: 'spring', damping: 22, stiffness: 300 },
    },
    exit: {
      opacity: 0, y: 30, scale: 0.9,
      transition: { duration: 0.2, ease: 'easeIn' },
    },
  };

  const maximizedVariants = {
    hidden: { opacity: 0, scale: 0.95 },
    visible: {
      opacity: 1, scale: 1,
      transition: { type: 'spring', damping: 25, stiffness: 200 },
    },
    exit: {
      opacity: 0, scale: 0.95,
      transition: { duration: 0.2 },
    },
  };

  const messageVariants = {
    hidden: { opacity: 0, y: 10, scale: 0.95 },
    visible: {
      opacity: 1, y: 0, scale: 1,
      transition: { type: 'spring', damping: 20, stiffness: 300 },
    },
  };

  return (
    <>
      {/* Floating Action Button */}
      <AnimatePresence>
        {!isOpen && (
          <motion.button
            key="fab"
            className="ai-chat-fab"
            variants={fabVariants}
            initial="idle"
            whileHover="hover"
            whileTap="tap"
            exit={{ scale: 0, opacity: 0 }}
            onClick={() => setIsOpen(true)}
            title="Ask SentinelAI Assistant"
          >
            <motion.div
              animate={{ rotate: [0, 10, -10, 0] }}
              transition={{ duration: 2, repeat: Infinity, repeatDelay: 3 }}
            >
              <Sparkles className="w-6 h-6" />
            </motion.div>
            <span className="ai-chat-fab-pulse" />
          </motion.button>
        )}
      </AnimatePresence>

      {/* Maximized backdrop */}
      <AnimatePresence>
        {isOpen && isMaximized && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-[998]"
            onClick={() => setIsMaximized(false)}
          />
        )}
      </AnimatePresence>

      {/* Chat Panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            key="panel"
            className={`ai-chat-panel ${isMaximized ? 'ai-chat-maximized' : ''}`}
            variants={isMaximized ? maximizedVariants : panelVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            layout
          >
            {/* Header */}
            <div className="ai-chat-header">
              <div className="flex items-center gap-2">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                  className="ai-chat-header-icon"
                >
                  <Bot className="w-5 h-5" />
                </motion.div>
                <div>
                  <h3 className="font-semibold text-sm">SentinelAI Assistant</h3>
                  <p className="text-[10px] text-white/50">Powered by Groq AI</p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {messages.length > 0 && (
                  <motion.button
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                    className="ai-chat-control-btn"
                    onClick={clearChat}
                    title="Clear chat"
                  >
                    <span className="text-xs">🗑️</span>
                  </motion.button>
                )}
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className="ai-chat-control-btn"
                  onClick={() => setIsMaximized(!isMaximized)}
                  title={isMaximized ? 'Minimize' : 'Maximize'}
                >
                  {isMaximized ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                </motion.button>
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className="ai-chat-control-btn"
                  onClick={() => { setIsOpen(false); setIsMaximized(false); }}
                  title="Close"
                >
                  <X className="w-4 h-4" />
                </motion.button>
              </div>
            </div>

            {/* Messages area */}
            <div className="ai-chat-messages" ref={scrollContainerRef}>
              {/* Welcome message */}
              {messages.length === 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="ai-chat-welcome"
                >
                  <motion.div
                    animate={{ y: [0, -8, 0] }}
                    transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                    className="ai-chat-welcome-icon"
                  >
                    <Sparkles className="w-8 h-8 text-white/80" />
                  </motion.div>
                  <h4 className="font-semibold text-base mb-1">How can I help you?</h4>
                  <p className="text-xs text-white/50 mb-4">
                    Ask me about security vulnerabilities, best practices, or anything related to your penetration testing workflow.
                  </p>
                </motion.div>
              )}

              {/* Hot Questions */}
              <AnimatePresence>
                {showHotQuestions && messages.length === 0 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0, height: 0 }}
                    className="ai-chat-hot-questions"
                  >
                    {HOT_QUESTIONS.map((q, i) => (
                      <motion.button
                        key={i}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.3 + i * 0.06 }}
                        whileHover={{ scale: 1.02, y: -1 }}
                        whileTap={{ scale: 0.98 }}
                        className="ai-chat-hot-btn"
                        onClick={() => sendMessage(q.prompt)}
                      >
                        {q.label}
                      </motion.button>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Message list */}
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  variants={messageVariants}
                  initial="hidden"
                  animate="visible"
                  className={`ai-chat-message ${msg.role === 'user' ? 'ai-chat-message-user' : 'ai-chat-message-ai'} ${msg.isError ? 'ai-chat-message-error' : ''}`}
                >
                  <div className="ai-chat-message-avatar">
                    {msg.role === 'user' ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
                  </div>
                  <div className="ai-chat-message-content">
                    {msg.content.split('\n').map((line, i) => (
                      <p key={i} className={i > 0 ? 'mt-1.5' : ''}>{line}</p>
                    ))}
                  </div>
                  {/* TTS speaker button on AI messages */}
                  {msg.role === 'assistant' && !msg.isError && voice.supported.tts && (
                    <motion.button
                      whileHover={{ scale: 1.15 }}
                      whileTap={{ scale: 0.9 }}
                      className={`ai-chat-speak-btn ${speakingMsgId === msg.id ? 'speaking' : ''}`}
                      onClick={() => handleSpeakMessage(msg)}
                      title={speakingMsgId === msg.id ? 'Stop reading' : 'Read aloud'}
                    >
                      {speakingMsgId === msg.id ? (
                        <VolumeX className="w-3 h-3" />
                      ) : (
                        <Volume2 className="w-3 h-3" />
                      )}
                    </motion.button>
                  )}
                </motion.div>
              ))}

              {/* Typing indicator */}
              {loading && <TypingIndicator />}

              <div ref={messagesEndRef} />
            </div>

            {/* Input area */}
            <div className="ai-chat-input-area">
              <div className="mb-2 rounded-2xl border border-white/10 bg-white/5 p-2.5 backdrop-blur-sm">
                <div className="flex gap-2">
                  <input
                    value={workspacePath}
                    onChange={(e) => setWorkspacePath(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        loadWorkspaceFile();
                      }
                    }}
                    placeholder="Load workspace file by path, e.g. frontend/src/components/AIChatWidget.jsx"
                    className="min-w-0 flex-1 rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-xs text-white placeholder:text-white/40 outline-none transition focus:border-cyan-400/60"
                  />
                  <motion.button
                    whileHover={{ scale: 1.04 }}
                    whileTap={{ scale: 0.97 }}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-cyan-400/30 bg-cyan-400/15 px-3 py-2 text-xs font-medium text-cyan-100 disabled:cursor-not-allowed disabled:opacity-50"
                    onClick={loadWorkspaceFile}
                    disabled={!workspacePath.trim() || loading || Boolean(fileBusyPath)}
                    title="Read a workspace file into chat"
                  >
                    <FolderOpen className="h-3.5 w-3.5" />
                    {fileBusyPath && fileBusyPath === workspacePath.trim() ? 'Loading...' : 'Load file'}
                  </motion.button>
                </div>

                {attachedFiles.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {attachedFiles.map((file) => (
                      <div
                        key={file.path}
                        className="flex max-w-full items-center gap-2 rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-[11px] text-white/80"
                      >
                        <div className="min-w-0">
                          <div className="truncate font-medium text-white">{file.path}</div>
                          <div className="text-white/45">
                            {typeof file.size === 'number' ? `${file.size} bytes` : 'Loaded file'}
                            {file.modifiedAt ? ` • ${new Date(file.modifiedAt).toLocaleString()}` : ''}
                          </div>
                        </div>

                        <motion.button
                          whileHover={{ scale: 1.08 }}
                          whileTap={{ scale: 0.95 }}
                          className="inline-flex items-center gap-1 rounded-lg border border-emerald-400/30 bg-emerald-400/15 px-2 py-1 text-[10px] text-emerald-100 disabled:opacity-50"
                          onClick={() => applyAssistantToFile(file)}
                          disabled={loading || Boolean(fileBusyPath)}
                          title="Write the latest AI reply back to this file"
                        >
                          <Save className="h-3 w-3" />
                          Apply reply
                        </motion.button>

                        <motion.button
                          whileHover={{ scale: 1.08 }}
                          whileTap={{ scale: 0.95 }}
                          className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[10px] text-white/70 disabled:opacity-50"
                          onClick={() => removeAttachment(file.path)}
                          disabled={loading}
                          title="Remove file from chat context"
                        >
                          <Trash2 className="h-3 w-3" />
                          Remove
                        </motion.button>
                      </div>
                    ))}
                  </div>
                )}
                <p className="mt-2 text-[10px] text-white/45">
                  Load a file from your workspace to give the assistant read access. Use “Apply reply” to write the last AI response back to that file.
                </p>
              </div>

              {messages.length > 0 && (
                <motion.button
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="ai-chat-suggestions-toggle"
                  onClick={() => setShowHotQuestions(!showHotQuestions)}
                >
                  <ChevronDown className={`w-3 h-3 transition-transform ${showHotQuestions ? 'rotate-180' : ''}`} />
                  <span className="text-[10px]">Quick questions</span>
                </motion.button>
              )}
              
              <AnimatePresence>
                {showHotQuestions && messages.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="ai-chat-hot-questions ai-chat-hot-questions-inline"
                  >
                    {HOT_QUESTIONS.slice(0, 3).map((q, i) => (
                      <motion.button
                        key={i}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className="ai-chat-hot-btn ai-chat-hot-btn-sm"
                        onClick={() => sendMessage(q.prompt)}
                      >
                        {q.label}
                      </motion.button>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Listening indicator */}
              <AnimatePresence>
                {voice.isListening && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="ai-chat-listening-bar"
                  >
                    <span className="ai-chat-listening-dot" />
                    <span className="text-[10px] text-red-400 font-medium">
                      Listening{voice.interimTranscript ? `: "${voice.interimTranscript}"` : '...'}
                    </span>
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="ai-chat-input-row">
                <textarea
                  ref={inputRef}
                  value={voice.isListening ? (voice.transcript + (voice.interimTranscript ? ' ' + voice.interimTranscript : '')) : input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={voice.isListening ? 'Listening... speak now' : 'Ask about security...'}
                  className="ai-chat-input"
                  rows={1}
                  disabled={loading || voice.isListening}
                />

                {/* Mic button */}
                {voice.supported.stt && (
                  <motion.button
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                    className={`ai-chat-mic-btn ${voice.isListening ? 'listening' : ''}`}
                    onClick={handleMicToggle}
                    disabled={loading}
                    title={voice.isListening ? 'Stop listening' : 'Voice input'}
                  >
                    {voice.isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
                  </motion.button>
                )}

                {/* Auto-speak toggle */}
                {voice.supported.tts && (
                  <motion.button
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                    className={`ai-chat-auto-speak-btn ${autoSpeak ? 'active' : ''}`}
                    onClick={() => setAutoSpeak(!autoSpeak)}
                    title={autoSpeak ? 'Auto-speak ON — click to disable' : 'Auto-speak OFF — click to enable'}
                  >
                    <Volume2 className="w-3.5 h-3.5" />
                  </motion.button>
                )}

                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className={`ai-chat-send-btn ${(input.trim() || attachedFiles.length > 0) && !loading ? 'active' : ''}`}
                  onClick={() => sendMessage(input)}
                  disabled={!(input.trim() || attachedFiles.length > 0) || loading}
                >
                  <Send className="w-4 h-4" />
                </motion.button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
