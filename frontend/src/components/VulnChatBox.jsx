import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquare, X, Send, Bot, User, ShieldAlert } from 'lucide-react';
import { apiFetch } from '../lib/api.js';

function getVulnHotQuestions(vuln) {
  const title = vuln?.title || 'this vulnerability';
  const severity = vuln?.severity || 'unknown';
  return [
    {
      label: '🔧 How to fix?',
      prompt: `How do I fix the vulnerability "${title}"? Provide specific, step-by-step remediation instructions.`,
    },
    {
      label: '⚠️ What is the risk?',
      prompt: `What are the security risks of "${title}" (severity: ${severity})? Explain the potential impact on the system.`,
    },
    {
      label: '🎯 Exploitability',
      prompt: `How easily can "${title}" be exploited by an attacker? What tools or techniques might they use?`,
    },
    {
      label: '🛡️ Mitigation',
      prompt: `What temporary mitigations can I apply for "${title}" while working on a permanent fix?`,
    },
    {
      label: '📋 CVSS Breakdown',
      prompt: `Break down the CVSS score for "${title}" (CVSS: ${vuln?.cvss ?? 'N/A'}, severity: ${severity}). Explain each vector.`,
    },
    {
      label: '🔍 Similar CVEs',
      prompt: `What are known CVEs similar to "${title}"? Are there any recent public exploits for this type of vulnerability?`,
    },
  ];
}

function TypingIndicator() {
  return (
    <div className="ai-chat-typing flex items-center gap-1 px-3 py-2">
      <Bot className="w-3.5 h-3.5 text-white/60 mr-1.5 flex-shrink-0" />
      <span className="typing-dot" />
      <span className="typing-dot" style={{ animationDelay: '0.15s' }} />
      <span className="typing-dot" style={{ animationDelay: '0.3s' }} />
    </div>
  );
}

export default function VulnChatBox({ vuln }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const hotQuestions = getVulnHotQuestions(vuln);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading, scrollToBottom]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 200);
    }
  }, [isOpen]);

  // Reset chat when vulnerability changes
  useEffect(() => {
    setMessages([]);
    setIsOpen(false);
  }, [vuln?.id]);

  async function sendMessage(text) {
    if (!text.trim() || loading) return;

    const userMsg = { role: 'user', content: text.trim(), id: Date.now() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await apiFetch('/api/ai/chat', {
        method: 'POST',
        body: {
          message: text.trim(),
          context: {
            type: 'vulnerability',
            vulnerability: {
              id: vuln?.id,
              title: vuln?.title,
              severity: vuln?.severity,
              cvss: vuln?.cvss,
              description: vuln?.description,
              asset: vuln?.asset,
              module: vuln?.module,
              cweId: vuln?.cweId,
              status: vuln?.status,
              remediation: vuln?.remediation,
            },
          },
          history: messages.slice(-8).map((m) => ({ role: m.role, content: m.content })),
        },
      });

      const aiMsg = {
        role: 'assistant',
        content: res.response || 'Unable to generate response. Please try again.',
        id: Date.now() + 1,
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      const errorMsg = {
        role: 'assistant',
        content: `⚠️ ${err.message || 'AI service unavailable.'}`,
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

  if (!vuln) return null;

  return (
    <>
      {/* Toggle button */}
      <motion.button
        whileHover={{ scale: 1.03 }}
        whileTap={{ scale: 0.97 }}
        className={`vuln-chat-toggle ${isOpen ? 'active' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
      >
        <motion.div
          animate={isOpen ? { rotate: 0 } : { rotate: [0, 15, -15, 0] }}
          transition={{ duration: 1.5, repeat: isOpen ? 0 : Infinity, repeatDelay: 4 }}
        >
          {isOpen ? <X className="w-4 h-4" /> : <MessageSquare className="w-4 h-4" />}
        </motion.div>
        <span className="text-sm font-medium">{isOpen ? 'Close AI Chat' : '🤖 Ask AI about this vulnerability'}</span>
      </motion.button>

      {/* Chat panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            className="vuln-chat-panel"
            initial={{ opacity: 0, height: 0, y: -10 }}
            animate={{ opacity: 1, height: 'auto', y: 0 }}
            exit={{ opacity: 0, height: 0, scale: 0.95 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          >
            {/* Header */}
            <div className="vuln-chat-header">
              <div className="flex items-center gap-2 min-w-0">
                <ShieldAlert className="w-4 h-4 text-white/60 flex-shrink-0" />
                <span className="text-xs font-medium truncate">
                  AI Analysis: {vuln.title?.slice(0, 40)}{vuln.title?.length > 40 ? '…' : ''}
                </span>
              </div>
            </div>

            {/* Messages */}
            <div className="vuln-chat-messages">
              {/* Hot questions at the top */}
              {messages.length === 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="vuln-chat-hot-area"
                >
                  <p className="text-[10px] text-white/40 mb-2 px-1">Quick questions about this vulnerability:</p>
                  <div className="vuln-chat-hot-grid">
                    {hotQuestions.map((q, i) => (
                      <motion.button
                        key={i}
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: i * 0.05 }}
                        whileHover={{ scale: 1.03, y: -1 }}
                        whileTap={{ scale: 0.97 }}
                        className="vuln-chat-hot-btn"
                        onClick={() => sendMessage(q.prompt)}
                      >
                        {q.label}
                      </motion.button>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* Message list */}
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`ai-chat-message ${msg.role === 'user' ? 'ai-chat-message-user' : 'ai-chat-message-ai'} ${msg.isError ? 'ai-chat-message-error' : ''}`}
                >
                  <div className="ai-chat-message-avatar ai-chat-message-avatar-sm">
                    {msg.role === 'user' ? <User className="w-3 h-3" /> : <Bot className="w-3 h-3" />}
                  </div>
                  <div className="ai-chat-message-content text-xs">
                    {msg.content.split('\n').map((line, i) => (
                      <p key={i} className={i > 0 ? 'mt-1' : ''}>{line}</p>
                    ))}
                  </div>
                </motion.div>
              ))}

              {loading && <TypingIndicator />}
              <div ref={messagesEndRef} />
            </div>

            {/* Quick actions when there are messages */}
            {messages.length > 0 && (
              <div className="vuln-chat-quick-scroll">
                {hotQuestions.map((q, i) => (
                  <motion.button
                    key={i}
                    whileHover={{ scale: 1.04 }}
                    whileTap={{ scale: 0.96 }}
                    className="vuln-chat-quick-pill"
                    onClick={() => sendMessage(q.prompt)}
                    disabled={loading}
                  >
                    {q.label}
                  </motion.button>
                ))}
              </div>
            )}

            {/* Input */}
            <div className="vuln-chat-input-area">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about this vulnerability..."
                className="vuln-chat-input"
                rows={1}
                disabled={loading}
              />
              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                className={`vuln-chat-send ${input.trim() && !loading ? 'active' : ''}`}
                onClick={() => sendMessage(input)}
                disabled={!input.trim() || loading}
              >
                <Send className="w-3.5 h-3.5" />
              </motion.button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
