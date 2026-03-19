import crypto from "node:crypto";

interface PasswordOptions {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  exclude_ambiguous?: boolean;
  count?: number;
}

interface GeneratedPassword {
  passwords: string[];
  length: number;
  charset_size: number;
  entropy_bits: number;
}

const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
  "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
  "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
  "michael", "football", "password1", "password123", "admin", "welcome",
  "hello", "charlie", "donald", "login", "princess", "starwars",
]);

const COMMON_PATTERNS = [
  { name: "all_lowercase", pattern: /^[a-z]+$/ },
  { name: "all_uppercase", pattern: /^[A-Z]+$/ },
  { name: "all_digits", pattern: /^\d+$/ },
  { name: "sequential_digits", pattern: /(?:012|123|234|345|456|567|678|789|890)/ },
  { name: "repeated_chars", pattern: /(.)\1{2,}/ },
  { name: "keyboard_pattern", pattern: /(?:qwert|asdf|zxcv|qazwsx|poiuy)/i },
  { name: "date_pattern", pattern: /(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/ },
];

export function generatePassword(options: PasswordOptions = {}): GeneratedPassword {
  const {
    length = 16,
    uppercase = true,
    lowercase = true,
    digits = true,
    symbols = true,
    exclude_ambiguous = false,
    count = 1,
  } = options;

  const len = Math.min(Math.max(4, length), 256);
  const n = Math.min(Math.max(1, count), 100);

  let chars = "";
  const required: string[] = [];

  const uppercaseChars = exclude_ambiguous ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lowercaseChars = exclude_ambiguous ? "abcdefghjkmnpqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz";
  const digitChars = exclude_ambiguous ? "23456789" : "0123456789";
  const symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (uppercase) { chars += uppercaseChars; required.push(uppercaseChars); }
  if (lowercase) { chars += lowercaseChars; required.push(lowercaseChars); }
  if (digits) { chars += digitChars; required.push(digitChars); }
  if (symbols) { chars += symbolChars; required.push(symbolChars); }

  if (chars.length === 0) {
    chars = lowercaseChars + uppercaseChars + digitChars;
    required.push(lowercaseChars, uppercaseChars, digitChars);
  }

  const passwords: string[] = [];

  for (let i = 0; i < n; i++) {
    let password: string;
    let attempts = 0;
    do {
      const bytes = crypto.randomBytes(len);
      const arr: string[] = [];
      for (let j = 0; j < len; j++) {
        arr.push(chars[bytes[j] % chars.length]);
      }
      // Ensure at least one character from each required set
      for (let r = 0; r < required.length && r < len; r++) {
        const reqSet = required[r];
        if (!arr.some((c) => reqSet.includes(c))) {
          const pos = crypto.randomInt(len);
          const randByte = crypto.randomBytes(1)[0];
          arr[pos] = reqSet[randByte % reqSet.length];
        }
      }
      password = arr.join("");
      attempts++;
    } while (attempts < 10 && required.some((req) => !password.split("").some((c) => req.includes(c))));
    passwords.push(password);
  }

  const charsetSize = chars.length;
  const entropyBits = Math.round(len * Math.log2(charsetSize) * 100) / 100;

  return { passwords, length: len, charset_size: charsetSize, entropy_bits: entropyBits };
}

interface StrengthResult {
  password_length: number;
  entropy_bits: number;
  strength: "very_weak" | "weak" | "fair" | "strong" | "very_strong";
  score: number;
  warnings: string[];
  crack_time_estimate: string;
  charset_size: number;
}

export function checkPasswordStrength(password: string): StrengthResult {
  const warnings: string[] = [];
  let charsetSize = 0;

  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/\d/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  if (charsetSize === 0) charsetSize = 1;

  const entropyBits = Math.round(password.length * Math.log2(charsetSize) * 100) / 100;

  // Check common passwords
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    warnings.push("This is a commonly used password");
  }

  // Check patterns
  for (const { name, pattern } of COMMON_PATTERNS) {
    if (pattern.test(password)) {
      warnings.push(`Contains ${name.replace(/_/g, " ")} pattern`);
    }
  }

  if (password.length < 8) warnings.push("Password is shorter than 8 characters");
  if (password.length < 12) warnings.push("Consider using 12+ characters");

  // Unique characters ratio
  const uniqueRatio = new Set(password).size / password.length;
  if (uniqueRatio < 0.5) warnings.push("Low character diversity");

  // Score calculation (0-100)
  let score = 0;
  score += Math.min(30, password.length * 2);
  score += Math.min(20, entropyBits / 4);
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 10;
  if (/\d/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 15;
  score += Math.min(15, uniqueRatio * 15);
  score -= warnings.length * 5;
  score = Math.max(0, Math.min(100, Math.round(score)));

  let strength: StrengthResult["strength"];
  if (score < 20) strength = "very_weak";
  else if (score < 40) strength = "weak";
  else if (score < 60) strength = "fair";
  else if (score < 80) strength = "strong";
  else strength = "very_strong";

  const crackTime = estimateCrackTime(entropyBits);

  return {
    password_length: password.length,
    entropy_bits: entropyBits,
    strength,
    score,
    warnings,
    crack_time_estimate: crackTime,
    charset_size: charsetSize,
  };
}

function estimateCrackTime(entropyBits: number): string {
  // Assume 10 billion guesses per second (modern GPU)
  const guessesPerSecond = 1e10;
  const totalGuesses = Math.pow(2, entropyBits);
  const seconds = totalGuesses / guessesPerSecond / 2; // average case

  if (seconds < 0.001) return "instant";
  if (seconds < 1) return "less than a second";
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000 * 1000) return `${Math.round(seconds / 31536000)} years`;
  if (seconds < 31536000 * 1e6) return `${Math.round(seconds / 31536000 / 1000)}k years`;
  if (seconds < 31536000 * 1e9) return `${Math.round(seconds / 31536000 / 1e6)}M years`;
  return "billions of years+";
}
