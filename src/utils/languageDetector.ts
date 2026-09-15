/**
 * Robust, lightweight natural language detector for RFC 5322 email bodies and headers.
 * Combines MIME Content-Language/Accept-Language header extraction, script-range analysis,
 * stopword scoring, and diacritic profiling.
 */

export interface DetectedLanguage {
  code: string;       // ISO 639-1 code (e.g., 'en', 'es', 'fr', 'de', 'ja', 'ru')
  name: string;       // Full human-readable display name (e.g., 'English', 'Spanish')
  nativeName?: string;// Native script name (e.g., 'Español', 'Français')
  confidence: number; // 0 - 100 confidence score
  direction?: 'ltr' | 'rtl';
}

interface LanguageProfile {
  code: string;
  name: string;
  nativeName: string;
  direction?: 'ltr' | 'rtl';
  scriptRegex?: RegExp;
  stopwords: string[];
}

const LANGUAGE_PROFILES: LanguageProfile[] = [
  {
    code: 'en',
    name: 'English',
    nativeName: 'English',
    stopwords: [
      'the', 'and', 'to', 'of', 'a', 'in', 'that', 'is', 'for', 'it', 'you', 'with', 'on', 'as',
      'be', 'at', 'this', 'have', 'from', 'or', 'by', 'your', 'we', 'an', 'not', 'are', 'account',
      'security', 'verify', 'please', 'immediate', 'action', 'dear', 'team', 'service', 'click', 'login'
    ],
  },
  {
    code: 'es',
    name: 'Spanish',
    nativeName: 'Español',
    stopwords: [
      'de', 'la', 'que', 'el', 'en', 'y', 'a', 'los', 'del', 'se', 'las', 'por', 'un', 'para',
      'con', 'no', 'una', 'su', 'al', 'es', 'lo', 'como', 'más', 'pero', 'sus', 'le', 'cuenta',
      'seguridad', 'estimado', 'inmediato', 'verifique', 'haga', 'clic', 'acceso', 'correo'
    ],
  },
  {
    code: 'fr',
    name: 'French',
    nativeName: 'Français',
    stopwords: [
      'de', 'la', 'le', 'et', 'les', 'des', 'en', 'un', 'du', 'une', 'que', 'est', 'pour',
      'qui', 'dans', 'ce', 'il', 'pas', 'sur', 'au', 'par', 'avec', 'plus', 'compte', 'sécurité',
      'veuillez', 'confirmer', 'immédiat', 'votre', 'accès', 'cliquez', 'cher', 'client'
    ],
  },
  {
    code: 'de',
    name: 'German',
    nativeName: 'Deutsch',
    stopwords: [
      'der', 'die', 'und', 'in', 'den', 'von', 'zu', 'das', 'mit', 'sich', 'des', 'auf', 'für',
      'ist', 'im', 'dem', 'nicht', 'ein', 'eine', 'als', 'auch', 'es', 'an', 'werden', 'konto',
      'sicherheit', 'bitte', 'bestätigen', 'sofort', 'ihr', 'zugang', 'klicken', 'sehr', 'geehrte'
    ],
  },
  {
    code: 'pt',
    name: 'Portuguese',
    nativeName: 'Português',
    stopwords: [
      'de', 'a', 'o', 'que', 'e', 'do', 'da', 'em', 'um', 'para', 'com', 'não', 'uma', 'os',
      'no', 'se', 'na', 'por', 'mais', 'as', 'dos', 'como', 'mas', 'foi', 'ao', 'conta', 'segurança',
      'favor', 'confirme', 'imediato', 'sua', 'seu', 'clique', 'acesso'
    ],
  },
  {
    code: 'it',
    name: 'Italian',
    nativeName: 'Italiano',
    stopwords: [
      'di', 'e', 'il', 'la', 'che', 'in', 'un', 'per', 'del', 'con', 'una', 'da', 'al', 'le',
      'non', 'si', 'dei', 'della', 'delle', 'conto', 'sicurezza', 'conferma', 'clicca', 'accesso',
      'gentile', 'urgente'
    ],
  },
  {
    code: 'nl',
    name: 'Dutch',
    nativeName: 'Nederlands',
    stopwords: [
      'de', 'en', 'van', 'het', 'in', 'een', 'op', 'dat', 'te', 'voor', 'is', 'met', 'om',
      'der', 'zijn', 'aan', 'rekening', 'beveiliging', 'bevestig', 'klik', 'onmiddellijk'
    ],
  },
  {
    code: 'ru',
    name: 'Russian',
    nativeName: 'Русский',
    scriptRegex: /[\u0400-\u04FF]/,
    stopwords: ['и', 'в', 'не', 'на', 'я', 'что', 'тот', 'быть', 'с', 'он', 'а', 'как', 'по', 'безопасность', 'аккаунт', 'подтвердите'],
  },
  {
    code: 'zh',
    name: 'Chinese',
    nativeName: '中文',
    scriptRegex: /[\u4E00-\u9FFF]/,
    stopwords: ['的', '一', '是', '在', '不', '了', '有', '和', '人', '这', '中', '安全', '验证', '账户', '立即'],
  },
  {
    code: 'ja',
    name: 'Japanese',
    nativeName: '日本語',
    scriptRegex: /[\u3040-\u309F\u30A0-\u30FF]/,
    stopwords: ['の', 'に', 'は', 'を', 'た', 'が', 'で', 'て', 'と', 'し', 'れ', 'アカウント', 'セキュリティ', '確認', '緊急'],
  },
  {
    code: 'ar',
    name: 'Arabic',
    nativeName: 'العربية',
    direction: 'rtl',
    scriptRegex: /[\u0600-\u06FF]/,
    stopwords: ['في', 'من', 'على', 'أن', 'إلى', 'هذا', 'هو', 'أو', 'لا', 'مع', 'حساب', 'أمان', 'تأكيد', 'عاجل'],
  },
  {
    code: 'hi',
    name: 'Hindi',
    nativeName: 'हिन्दी',
    scriptRegex: /[\u0900-\u097F]/,
    stopwords: ['के', 'है', 'की', 'में', 'को', 'और', 'से', 'का', 'एक', 'यह', 'सुरक्षा', 'खाता', 'पुष्टि'],
  },
];

/**
 * Detect language of an RFC 5322 email string (inspecting both headers and content body)
 */
export function detectEmailLanguage(rawEmlOrText: string): DetectedLanguage {
  if (!rawEmlOrText || rawEmlOrText.trim().length === 0) {
    return { code: 'en', name: 'English', nativeName: 'English', confidence: 50 };
  }

  // 1. Inspect explicit RFC headers if present: Content-Language, Accept-Language, X-Language
  const contentLangMatch = rawEmlOrText.match(/^(?:Content-Language|Accept-Language|X-Language):\s*([a-zA-Z]{2,3}(?:-[a-zA-Z0-9]+)?)/im);
  if (contentLangMatch && contentLangMatch[1]) {
    const rawTag = contentLangMatch[1].trim().toLowerCase().slice(0, 2);
    const profile = LANGUAGE_PROFILES.find(p => p.code === rawTag);
    if (profile) {
      return {
        code: profile.code,
        name: profile.name,
        nativeName: profile.nativeName,
        direction: profile.direction || 'ltr',
        confidence: 96,
      };
    }
  }

  // 2. Separate body text from headers
  const splitIdx = rawEmlOrText.search(/\r?\n\r?\n/);
  const bodyText = splitIdx !== -1 ? rawEmlOrText.slice(splitIdx) : rawEmlOrText;

  // Extract Subject line if available
  const subjectMatch = rawEmlOrText.match(/^Subject:\s*(.+)$/im);
  const subjectText = subjectMatch ? subjectMatch[1].trim() : '';

  const sampleText = `${subjectText} ${bodyText}`.slice(0, 4000);

  // 3. Check for specific non-Latin Unicode script ranges first (Japanese, Chinese, Russian, Arabic, Hindi)
  const scriptCounts = {
    ja: (sampleText.match(/[\u3040-\u309F\u30A0-\u30FF]/g) || []).length,
    zh: (sampleText.match(/[\u4E00-\u9FFF]/g) || []).length,
    ru: (sampleText.match(/[\u0400-\u04FF]/g) || []).length,
    ar: (sampleText.match(/[\u0600-\u06FF]/g) || []).length,
    hi: (sampleText.match(/[\u0900-\u097F]/g) || []).length,
  };

  // Japanese has kana + kanji
  if (scriptCounts.ja > 15) {
    const profile = LANGUAGE_PROFILES.find(p => p.code === 'ja')!;
    return { code: profile.code, name: profile.name, nativeName: profile.nativeName, confidence: 95 };
  }
  if (scriptCounts.zh > 25 && scriptCounts.ja < 5) {
    const profile = LANGUAGE_PROFILES.find(p => p.code === 'zh')!;
    return { code: profile.code, name: profile.name, nativeName: profile.nativeName, confidence: 92 };
  }
  if (scriptCounts.ru > 15) {
    const profile = LANGUAGE_PROFILES.find(p => p.code === 'ru')!;
    return { code: profile.code, name: profile.name, nativeName: profile.nativeName, confidence: 94 };
  }
  if (scriptCounts.ar > 15) {
    const profile = LANGUAGE_PROFILES.find(p => p.code === 'ar')!;
    return { code: profile.code, name: profile.name, nativeName: profile.nativeName, direction: 'rtl', confidence: 95 };
  }
  if (scriptCounts.hi > 15) {
    const profile = LANGUAGE_PROFILES.find(p => p.code === 'hi')!;
    return { code: profile.code, name: profile.name, nativeName: profile.nativeName, confidence: 93 };
  }

  // 4. Latin-based stopword frequency analysis
  const normalizedWords = sampleText
    .toLowerCase()
    .replace(/[^a-z\u00C0-\u017F\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length >= 2);

  if (normalizedWords.length === 0) {
    return { code: 'en', name: 'English', nativeName: 'English', confidence: 60 };
  }

  const wordSet = new Set(normalizedWords);
  const wordFrequencyMap: Record<string, number> = {};
  for (const w of normalizedWords) {
    wordFrequencyMap[w] = (wordFrequencyMap[w] || 0) + 1;
  }

  let bestProfile = LANGUAGE_PROFILES[0]; // default English
  let bestScore = -1;

  for (const profile of LANGUAGE_PROFILES) {
    if (profile.scriptRegex) continue; // already evaluated script checks

    let score = 0;
    for (const stopword of profile.stopwords) {
      if (wordSet.has(stopword)) {
        score += (wordFrequencyMap[stopword] || 1) * 2;
      }
    }

    if (score > bestScore) {
      bestScore = score;
      bestProfile = profile;
    }
  }

  // Diacritic / special letter weighting
  if (/[äöüß]/i.test(sampleText)) {
    if (bestProfile.code !== 'de') {
      const deProfile = LANGUAGE_PROFILES.find(p => p.code === 'de')!;
      bestProfile = deProfile;
      bestScore += 10;
    }
  } else if (/[áéíóúñ¿¡]/i.test(sampleText)) {
    if (bestProfile.code !== 'es' && bestProfile.code !== 'pt') {
      const esProfile = LANGUAGE_PROFILES.find(p => p.code === 'es')!;
      bestProfile = esProfile;
      bestScore += 10;
    }
  } else if (/[ãõçê]/i.test(sampleText)) {
    const ptProfile = LANGUAGE_PROFILES.find(p => p.code === 'pt')!;
    bestProfile = ptProfile;
    bestScore += 10;
  } else if (/[éèêëàâùûîïôç]/i.test(sampleText)) {
    if (bestProfile.code !== 'fr') {
      const frProfile = LANGUAGE_PROFILES.find(p => p.code === 'fr')!;
      bestProfile = frProfile;
      bestScore += 10;
    }
  }

  // Calculate confidence
  const confidence = Math.min(99, Math.max(65, 60 + Math.min(38, bestScore * 2)));

  return {
    code: bestProfile.code,
    name: bestProfile.name,
    nativeName: bestProfile.nativeName,
    direction: bestProfile.direction || 'ltr',
    confidence,
  };
}
