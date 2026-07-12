import { useState, useCallback, useRef, useEffect } from 'react';

/**
 * useVoice — a reusable React hook for browser-native STT and TTS.
 *
 * STT: Uses the Web Speech API (SpeechRecognition / webkitSpeechRecognition)
 * TTS: Uses the Web Speech API (speechSynthesis)
 *
 * Both are 100 % free and run entirely in the browser.
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Strip markdown formatting so spoken output sounds natural. */
function stripMarkdown(text) {
  return text
    .replace(/```[\s\S]*?```/g, ' code block omitted ')  // code blocks
    .replace(/`([^`]+)`/g, '$1')                          // inline code
    .replace(/#{1,6}\s+/g, '')                            // headings
    .replace(/\*\*([^*]+)\*\*/g, '$1')                    // bold
    .replace(/\*([^*]+)\*/g, '$1')                        // italic
    .replace(/__([^_]+)__/g, '$1')                        // bold (alt)
    .replace(/_([^_]+)_/g, '$1')                          // italic (alt)
    .replace(/~~([^~]+)~~/g, '$1')                        // strikethrough
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')              // links
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, '$1')             // images
    .replace(/^\s*[-*+]\s+/gm, '• ')                     // list items
    .replace(/^\s*\d+\.\s+/gm, '')                       // numbered lists
    .replace(/>\s?/g, '')                                  // blockquotes
    .replace(/\|/g, ', ')                                  // table pipes
    .replace(/---+/g, '')                                  // horizontal rules
    .replace(/\n{2,}/g, '. ')                             // double newlines
    .replace(/\n/g, ' ')                                   // single newlines
    .replace(/\s{2,}/g, ' ')                              // extra spaces
    .trim();
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useVoice({ lang = 'en-US', continuous = true } = {}) {
  // ── State ──────────────────────────────────────────────────────────────────
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [interimTranscript, setInterimTranscript] = useState('');
  const [error, setError] = useState(null);

  const recognitionRef = useRef(null);
  const utteranceRef = useRef(null);

  // ── Feature detection ──────────────────────────────────────────────────────
  const supported = {
    stt: typeof window !== 'undefined' && ('SpeechRecognition' in window || 'webkitSpeechRecognition' in window),
    tts: typeof window !== 'undefined' && 'speechSynthesis' in window,
  };

  // ── STT ────────────────────────────────────────────────────────────────────

  const startListening = useCallback(() => {
    if (!supported.stt) {
      setError('Speech recognition is not supported in this browser.');
      return;
    }

    // Stop any existing recognition
    if (recognitionRef.current) {
      try { recognitionRef.current.stop(); } catch { /* noop */ }
    }

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition = new SpeechRecognition();

    recognition.lang = lang;
    recognition.interimResults = true;
    recognition.continuous = continuous;
    recognition.maxAlternatives = 1;

    recognition.onstart = () => {
      setIsListening(true);
      setError(null);
    };

    recognition.onresult = (event) => {
      let interim = '';
      let final = '';

      for (let i = event.resultIndex; i < event.results.length; i++) {
        const t = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          final += t;
        } else {
          interim += t;
        }
      }

      if (final) {
        setTranscript((prev) => (prev ? prev + ' ' : '') + final);
        setInterimTranscript('');
      } else {
        setInterimTranscript(interim);
      }
    };

    recognition.onerror = (event) => {
      // 'no-speech' and 'aborted' are expected and harmless
      if (event.error !== 'no-speech' && event.error !== 'aborted') {
        setError(`Speech recognition error: ${event.error}`);
      }
      setIsListening(false);
    };

    recognition.onend = () => {
      setIsListening(false);
      setInterimTranscript('');
    };

    recognitionRef.current = recognition;
    setTranscript('');
    setInterimTranscript('');
    recognition.start();
  }, [lang, continuous, supported.stt]);

  const stopListening = useCallback(() => {
    if (recognitionRef.current) {
      try { recognitionRef.current.stop(); } catch { /* noop */ }
      recognitionRef.current = null;
    }
    setIsListening(false);
    setInterimTranscript('');
  }, []);

  // ── TTS ────────────────────────────────────────────────────────────────────

  const speak = useCallback((text, { rate = 1, pitch = 1, voiceURI } = {}) => {
    if (!supported.tts || !text) return;

    // Cancel any ongoing speech
    window.speechSynthesis.cancel();

    const cleaned = stripMarkdown(text);
    const utterance = new SpeechSynthesisUtterance(cleaned);

    utterance.lang = lang;
    utterance.rate = rate;
    utterance.pitch = pitch;

    // Try to pick the requested voice
    if (voiceURI) {
      const voices = window.speechSynthesis.getVoices();
      const match = voices.find((v) => v.voiceURI === voiceURI);
      if (match) utterance.voice = match;
    }

    utterance.onstart = () => setIsSpeaking(true);
    utterance.onend = () => setIsSpeaking(false);
    utterance.onerror = () => setIsSpeaking(false);

    utteranceRef.current = utterance;
    window.speechSynthesis.speak(utterance);
  }, [lang, supported.tts]);

  const stopSpeaking = useCallback(() => {
    if (supported.tts) {
      window.speechSynthesis.cancel();
    }
    setIsSpeaking(false);
  }, [supported.tts]);

  // ── Available voices (for optional voice picker) ───────────────────────────
  const [voices, setVoices] = useState([]);

  useEffect(() => {
    if (!supported.tts) return;

    function loadVoices() {
      setVoices(window.speechSynthesis.getVoices());
    }

    loadVoices();
    window.speechSynthesis.addEventListener('voiceschanged', loadVoices);
    return () => {
      window.speechSynthesis.removeEventListener('voiceschanged', loadVoices);
    };
  }, [supported.tts]);

  // ── Cleanup on unmount ─────────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      if (recognitionRef.current) {
        try { recognitionRef.current.stop(); } catch { /* noop */ }
      }
      if (supported.tts) {
        window.speechSynthesis.cancel();
      }
    };
  }, [supported.tts]);

  return {
    // STT
    startListening,
    stopListening,
    isListening,
    transcript,
    interimTranscript,

    // TTS
    speak,
    stopSpeaking,
    isSpeaking,

    // Meta
    voices,
    supported,
    error,
    setTranscript,
  };
}
