/*
 * DESTINATION AI  -  single-file full-stack web application (Java 21, no external libraries)
 *
 * Run:      java DestinationAI.java
 * Open:     http://localhost:8080
 *
 * Environment variables (all optional):
 *   PORT=8080            HOST=127.0.0.1 (use 0.0.0.0 to allow other devices)
 *   DATA_DIR=data        SECURE_COOKIES=true (set when served over HTTPS)
 *
 * Data layout (inside DATA_DIR):
 *   users.tsv, goals.tsv     accounts and plans (flat files, atomic writes)
 *   lang/<code>.tsv          optional language packs, one line per entry:
 *                            <English text><TAB><translation>   (lines starting with # are comments)
 *
 * Languages: 50 languages are selectable. English and Bangla are built in.
 * Any other language shows English until its pack file exists. Packs are read on
 * every request, so adding or editing one needs no restart. The left column must
 * match the English text exactly as it appears in the app.
 */
import com.sun.net.httpserver.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.stream.*;

public class DestinationAI {

    // ===================================================================== CONFIG
    static String env(String k, String d) { String v = System.getenv(k); return v == null || v.isBlank() ? d : v; }
    static final int PORT = Integer.parseInt(env("PORT", "8080"));
    static final String HOST = env("HOST", "127.0.0.1");
    static final boolean SECURE = Boolean.parseBoolean(env("SECURE_COOKIES", "false"));
    static final Path DATA_DIR = Paths.get(env("DATA_DIR", "data"));
    static final long SESSION_MS = 7L * 24 * 3600 * 1000;
    static final SecureRandom RNG = new SecureRandom();
    static final Base64.Encoder B64 = Base64.getEncoder(), B64U = Base64.getUrlEncoder().withoutPadding();
    static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    static class ApiError extends RuntimeException {
        final int status;
        ApiError(int status, String msg) { super(msg); this.status = status; }
    }
    static ApiError bad() { return new ApiError(400, "Invalid input.||ভুল ইনপুট।"); }

    // ===================================================================== JSON (output only)
    static Map<String, Object> o(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
    static String json(Object v) { StringBuilder sb = new StringBuilder(); js(sb, v); return sb.toString(); }
    static void js(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof String s) {
            sb.append('"');
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    default -> { if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c); }
                }
            }
            sb.append('"');
        } else if (v instanceof Number || v instanceof Boolean) sb.append(v);
        else if (v instanceof Map<?, ?> m) {
            sb.append('{'); boolean first = true;
            for (var e : m.entrySet()) { if (!first) sb.append(','); first = false; js(sb, String.valueOf(e.getKey())); sb.append(':'); js(sb, e.getValue()); }
            sb.append('}');
        } else if (v instanceof Collection<?> c) {
            sb.append('['); boolean first = true;
            for (Object x : c) { if (!first) sb.append(','); first = false; js(sb, x); }
            sb.append(']');
        } else js(sb, v.toString());
    }

    // ===================================================================== PERSISTENCE (flat files, atomic writes)
    record User(String id, String email, String name, String salt, String hash, long created) {}
    record Goal(String id, String userId, String domain, String task, String title, String level,
                int weeks, int hours, long created, String done) {}

    static final class Store {
        final Map<String, User> users = new LinkedHashMap<>();
        final Map<String, Goal> goals = new LinkedHashMap<>();
        final Path uf, gf;
        Store(Path dir) throws IOException {
            Files.createDirectories(dir);
            uf = dir.resolve("users.tsv"); gf = dir.resolve("goals.tsv");
            if (Files.exists(uf)) for (String l : Files.readAllLines(uf, StandardCharsets.UTF_8)) {
                String[] p = l.split("\t", -1);
                if (p.length >= 6) users.put(p[0], new User(p[0], p[1], p[2], p[3], p[4], Long.parseLong(p[5])));
            }
            if (Files.exists(gf)) for (String l : Files.readAllLines(gf, StandardCharsets.UTF_8)) {
                String[] p = l.split("\t", -1);
                if (p.length >= 10) goals.put(p[0], new Goal(p[0], p[1], p[2], p[3], p[4], p[5],
                        Integer.parseInt(p[6]), Integer.parseInt(p[7]), Long.parseLong(p[8]), p[9]));
            }
        }
        static String c(String s) { return s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' '); }
        void write(Path p, List<String> lines) {
            try {
                Path tmp = p.resolveSibling(p.getFileName() + ".tmp");
                Files.write(tmp, lines, StandardCharsets.UTF_8);
                try { Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
                catch (AtomicMoveNotSupportedException e) { Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING); }
            } catch (IOException e) { throw new UncheckedIOException(e); }
        }
        void flushUsers() {
            write(uf, users.values().stream().map(u -> String.join("\t", u.id(), u.email(), c(u.name()),
                    u.salt(), u.hash(), String.valueOf(u.created()))).collect(Collectors.toList()));
        }
        void flushGoals() {
            write(gf, goals.values().stream().map(g -> String.join("\t", g.id(), g.userId(), g.domain(), g.task(),
                    c(g.title()), g.level(), String.valueOf(g.weeks()), String.valueOf(g.hours()),
                    String.valueOf(g.created()), g.done())).collect(Collectors.toList()));
        }
        synchronized User byEmail(String email) { return users.values().stream().filter(u -> u.email().equals(email)).findFirst().orElse(null); }
        synchronized User user(String id) { return users.get(id); }
        synchronized User addUser(String email, String name, String salt, String hash) {
            if (byEmail(email) != null) throw new ApiError(409, "An account with this email already exists.||এই ইমেইলে আগে থেকেই একটি অ্যাকাউন্ট আছে।");
            User u = new User(rid(), email, name, salt, hash, System.currentTimeMillis());
            users.put(u.id(), u); flushUsers(); return u;
        }
        synchronized void deleteUser(String id) {
            users.remove(id); goals.values().removeIf(g -> g.userId().equals(id)); flushUsers(); flushGoals();
        }
        synchronized List<Goal> goalsOf(String uid) {
            return goals.values().stream().filter(g -> g.userId().equals(uid))
                    .sorted(Comparator.comparingLong(Goal::created).reversed()).collect(Collectors.toList());
        }
        synchronized Goal goal(String id, String uid) {
            Goal g = goals.get(id);
            if (g == null || !g.userId().equals(uid)) throw new ApiError(404, "Plan not found.||পরিকল্পনা পাওয়া যায়নি।");
            return g;
        }
        synchronized void putGoal(Goal g) { goals.put(g.id(), g); flushGoals(); }
        synchronized void removeGoal(String id) { goals.remove(id); flushGoals(); }
    }
    static Store store;
    static String rid() { byte[] b = new byte[9]; RNG.nextBytes(b); return B64U.encodeToString(b); }

    // ===================================================================== AUTH
    record Session(String userId, long expires) {}
    static final ConcurrentHashMap<String, Session> SESSIONS = new ConcurrentHashMap<>();
    static final ConcurrentHashMap<String, Deque<Long>> ATTEMPTS = new ConcurrentHashMap<>();
    static final byte[] DUMMY_SALT = new byte[16];

    static String hashPw(String pw, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pw.toCharArray(), salt, 210_000, 256);
            return B64.encodeToString(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded());
        } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    static void rateCheck(String key, int max, long windowMs) {
        Deque<Long> d = ATTEMPTS.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (d) {
            long now = System.currentTimeMillis();
            while (!d.isEmpty() && now - d.peekFirst() > windowMs) d.pollFirst();
            if (d.size() >= max) throw new ApiError(429, "Too many attempts. Please try again later.||অনেকবার চেষ্টা করা হয়েছে। একটু পরে আবার চেষ্টা করুন।");
        }
    }
    static void rateHit(String key) {
        Deque<Long> d = ATTEMPTS.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (d) { d.addLast(System.currentTimeMillis()); }
    }
    static void startSession(HttpExchange ex, String uid) {
        byte[] b = new byte[32]; RNG.nextBytes(b);
        String tok = B64U.encodeToString(b);
        SESSIONS.put(tok, new Session(uid, System.currentTimeMillis() + SESSION_MS));
        cookie(ex, tok, SESSION_MS / 1000);
    }
    static void cookie(HttpExchange ex, String val, long maxAge) {
        ex.getResponseHeaders().add("Set-Cookie", "sid=" + val + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + maxAge + (SECURE ? "; Secure" : ""));
    }
    static String sessionToken(HttpExchange ex) {
        String c = ex.getRequestHeaders().getFirst("Cookie");
        if (c == null) return null;
        for (String part : c.split(";")) { part = part.trim(); if (part.startsWith("sid=")) return part.substring(4); }
        return null;
    }
    static User currentUser(HttpExchange ex) {
        String tok = sessionToken(ex);
        if (tok == null) return null;
        Session s = SESSIONS.get(tok);
        if (s == null || s.expires() < System.currentTimeMillis()) { SESSIONS.remove(tok); return null; }
        return store.user(s.userId());
    }
    static User need(HttpExchange ex) {
        User u = currentUser(ex);
        if (u == null) throw new ApiError(401, "Please log in first.||প্রথমে লগইন করুন।");
        return u;
    }
    static Map<String, Object> pub(User u) { return o("id", u.id(), "name", u.name(), "email", u.email()); }

    // ===================================================================== LANGUAGES
    // 50 widely spoken languages (approximate ranking by total speakers).
    // Row = {code, native name, "rtl" for right-to-left scripts or ""}.
    static final String[][] LANGS = {
        {"en", "English", ""}, {"zh", "中文", ""}, {"hi", "हिन्दी", ""}, {"es", "Español", ""}, {"fr", "Français", ""},
        {"ar", "العربية", "rtl"}, {"bn", "বাংলা", ""}, {"pt", "Português", ""}, {"ru", "Русский", ""}, {"ur", "اردو", "rtl"},
        {"id", "Bahasa Indonesia", ""}, {"de", "Deutsch", ""}, {"ja", "日本語", ""}, {"sw", "Kiswahili", ""}, {"mr", "मराठी", ""},
        {"te", "తెలుగు", ""}, {"tr", "Türkçe", ""}, {"ta", "தமிழ்", ""}, {"vi", "Tiếng Việt", ""}, {"ko", "한국어", ""},
        {"it", "Italiano", ""}, {"th", "ไทย", ""}, {"gu", "ગુજરાતી", ""}, {"fa", "فارسی", "rtl"}, {"pl", "Polski", ""},
        {"ps", "پښتو", "rtl"}, {"kn", "ಕನ್ನಡ", ""}, {"ml", "മലയാളം", ""}, {"pa", "ਪੰਜਾਬੀ", ""}, {"my", "မြန်မာ", ""},
        {"uk", "Українська", ""}, {"ms", "Bahasa Melayu", ""}, {"ne", "नेपाली", ""}, {"si", "සිංහල", ""}, {"fil", "Filipino", ""},
        {"nl", "Nederlands", ""}, {"ro", "Română", ""}, {"hu", "Magyar", ""}, {"el", "Ελληνικά", ""}, {"cs", "Čeština", ""},
        {"sv", "Svenska", ""}, {"he", "עברית", "rtl"}, {"am", "አማርኛ", ""}, {"ha", "Hausa", ""}, {"yo", "Yorùbá", ""},
        {"az", "Azərbaycanca", ""}, {"uz", "Oʻzbekcha", ""}, {"km", "ខ្មែរ", ""}, {"so", "Soomaali", ""}, {"zu", "isiZulu", ""}};

    /** Loads DATA_DIR/lang/<code>.tsv. The code is checked against LANGS first, so no path tricks are possible. */
    static Map<String, String> langPack(String code) throws IOException {
        if (Arrays.stream(LANGS).noneMatch(l -> l[0].equals(code))) throw new ApiError(404, "Unknown language.||অজানা ভাষা।");
        Map<String, String> m = new LinkedHashMap<>();
        Path p = DATA_DIR.resolve("lang").resolve(code + ".tsv");
        if (Files.exists(p)) for (String l : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            if (l.isBlank() || l.startsWith("#")) continue;
            String[] kv = l.split("\t", 2);
            if (kv.length == 2 && !kv[1].isBlank()) m.put(kv[0].trim(), kv[1].trim());
        }
        return m;
    }

    // ===================================================================== DOMAIN DATA
    static String bi(String en, String bn) { return en + "||" + bn; }
    static String bnDigits(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) sb.append(c >= '0' && c <= '9' ? (char) ('০' + (c - '0')) : c);
        return sb.toString();
    }

    static final String[][] DOMAINS = {
        {"education", "Education", "শিক্ষা"},
        {"career", "Career & Jobs", "ক্যারিয়ার ও চাকরি"},
        {"exams", "Exams & Certifications", "পরীক্ষা ও সার্টিফিকেশন"},
        {"business", "Entrepreneurship", "উদ্যোক্তা ও ব্যবসা"},
        {"skills", "Skills & Personal Growth", "দক্ষতা ও ব্যক্তিগত উন্নয়ন"}};

    static final String[] OTHER = {"other", "Other (describe it yourself)", "অন্য কিছু (নিজে লিখুন)"};
    static final Map<String, String[][]> TASKS = Map.of(
        "education", new String[][]{
            {"choose", "Choose a subject or university after admission", "ভর্তির পর বিষয় বা বিশ্ববিদ্যালয় বাছাই"},
            {"admission", "Prepare for an admission test", "ভর্তি পরীক্ষার প্রস্তুতি"},
            {"prestart", "Prepare before classes begin", "ক্লাস শুরুর আগে প্রস্তুতি"},
            {"abroad", "Plan study abroad or a scholarship", "বিদেশে পড়াশোনা বা বৃত্তির পরিকল্পনা"}, OTHER},
        "career", new String[][]{
            {"discover", "Discover a suitable career", "উপযুক্ত ক্যারিয়ার খোঁজা"},
            {"jobsearch", "Plan a job search", "চাকরি খোঁজার পরিকল্পনা"},
            {"roleskill", "Build skills for a specific role", "নির্দিষ্ট পদের জন্য দক্ষতা অর্জন"},
            {"interview", "Prepare for interviews", "ইন্টারভিউ প্রস্তুতি"}, OTHER},
        "exams", new String[][]{
            {"admission", "University admission test", "বিশ্ববিদ্যালয় ভর্তি পরীক্ষা"},
            {"govjob", "Government or competitive job exam", "সরকারি বা প্রতিযোগিতামূলক চাকরির পরীক্ষা"},
            {"language", "Language test (e.g. IELTS)", "ভাষা পরীক্ষা (যেমন আইইএলটিএস)"},
            {"cert", "Professional certification", "পেশাগত সার্টিফিকেশন"}, OTHER},
        "business", new String[][]{
            {"idea", "Choose a business idea", "ব্যবসার আইডিয়া বাছাই"},
            {"validate", "Validate an idea before spending money", "টাকা খরচের আগে আইডিয়া যাচাই"},
            {"launch", "Plan and launch a first version", "প্রথম সংস্করণ পরিকল্পনা ও চালু"}, OTHER},
        "skills", new String[][]{
            {"learn", "Learn a new skill", "নতুন দক্ষতা শেখা"},
            {"project", "Finish a personal project", "ব্যক্তিগত প্রজেক্ট শেষ করা"},
            {"habit", "Build a study or work habit", "পড়াশোনা বা কাজের অভ্যাস গড়া"}, OTHER});

    static final String[][] TAGS = {
        {"tech", "Technology", "প্রযুক্তি"}, {"people", "Working with people", "মানুষের সাথে কাজ"},
        {"business", "Business & money", "ব্যবসা ও অর্থ"}, {"creative", "Creative work", "সৃজনশীল কাজ"},
        {"analysis", "Analysis & problem-solving", "বিশ্লেষণ ও সমস্যা সমাধান"},
        {"hands", "Hands-on building", "হাতে-কলমে কাজ"}, {"writing", "Writing & communication", "লেখা ও যোগাযোগ"}};

    record Dest(String id, String en, String bn, String tags, int inc, int stab, int cre, int imp, int hard, String tEn, String tBn) {}
    static final Map<String, List<Dest>> DESTS = Map.of(
        "education", List.of(
            new Dest("cse", "Computer Science & Software", "কম্পিউটার সায়েন্স ও সফটওয়্যার", "tech,analysis", 4, 3, 3, 3, 4,
                "In demand, but competitive; needs steady practice and the field changes quickly.",
                "চাহিদা আছে, তবে প্রতিযোগিতা বেশি; নিয়মিত অনুশীলন লাগে এবং ক্ষেত্রটি দ্রুত বদলায়।"),
            new Dest("bba", "Business Administration (BBA)", "ব্যবসা প্রশাসন (বিবিএ)", "business,people", 3, 3, 2, 3, 2,
                "Broad and flexible, but outcomes depend heavily on internships and communication skills.",
                "পরিসর বড় ও নমনীয়, তবে ফল অনেকটা ইন্টার্নশিপ ও যোগাযোগ দক্ষতার ওপর নির্ভর করে।"),
            new Dest("eng", "Core Engineering (EEE, Civil, Mechanical)", "মূল প্রকৌশল (ইইই, সিভিল, মেকানিক্যাল)", "hands,analysis", 3, 4, 2, 4, 5,
                "Strong foundations and recognised paths, but demanding coursework and tough entry.",
                "শক্ত ভিত্তি ও স্বীকৃত পথ, তবে পড়াশোনার চাপ বেশি এবং ভর্তি কঠিন।"),
            new Dest("hum", "Humanities & Social Sciences", "মানবিক ও সামাজিক বিজ্ঞান", "writing,people", 2, 3, 3, 5, 2,
                "Builds writing and thinking skills; career paths are less direct and need active planning.",
                "লেখা ও চিন্তার দক্ষতা বাড়ায়; ক্যারিয়ারের পথ কম সরাসরি, তাই সক্রিয় পরিকল্পনা দরকার।")),
        "career", List.of(
            new Dest("software", "Software Developer", "সফটওয়্যার ডেভেলপার", "tech,analysis", 4, 3, 3, 3, 4,
                "Good demand, but entry-level roles are competitive and need a portfolio.",
                "চাহিদা ভালো, তবে শুরুর পদে প্রতিযোগিতা বেশি এবং পোর্টফোলিও লাগে।"),
            new Dest("data", "Data or Business Analyst", "ডেটা বা বিজনেস অ্যানালিস্ট", "analysis,business", 4, 3, 2, 3, 3,
                "Needs comfort with numbers, spreadsheets and SQL; roles vary a lot between employers.",
                "সংখ্যা, স্প্রেডশিট ও এসকিউএল-এ স্বচ্ছন্দ হতে হয়; নিয়োগকর্তাভেদে কাজ অনেক আলাদা।"),
            new Dest("marketing", "Digital Marketing & Content", "ডিজিটাল মার্কেটিং ও কনটেন্ট", "creative,writing,business", 3, 2, 5, 2, 2,
                "Easy to start and creative, but results can be uneven and tools change fast.",
                "শুরু করা সহজ ও সৃজনশীল, তবে ফল অনিয়মিত হতে পারে এবং টুল দ্রুত বদলায়।"),
            new Dest("design", "UI/UX & Graphic Design", "ইউআই/ইউএক্স ও গ্রাফিক ডিজাইন", "creative,tech", 3, 2, 5, 2, 3,
                "A portfolio matters more than certificates; clients and taste take time to build.",
                "সার্টিফিকেটের চেয়ে পোর্টফোলিও বেশি গুরুত্বপূর্ণ; ক্লায়েন্ট ও রুচি গড়তে সময় লাগে।"),
            new Dest("teach", "Teaching & Training", "শিক্ষকতা ও প্রশিক্ষণ", "people,writing", 2, 4, 3, 5, 2,
                "Meaningful and fairly stable, but income usually grows slowly.",
                "অর্থবহ ও মোটামুটি স্থিতিশীল, তবে আয় সাধারণত ধীরে বাড়ে।")),
        "exams", List.of(
            new Dest("adm", "University Admission Test", "বিশ্ববিদ্যালয় ভর্তি পরীক্ষা", "analysis,writing", 3, 4, 1, 3, 4,
                "Very competitive with fixed dates; depends on consistent preparation.",
                "প্রতিযোগিতা খুব বেশি ও তারিখ নির্দিষ্ট; নিয়মিত প্রস্তুতির ওপর নির্ভর করে।"),
            new Dest("gov", "Government or Competitive Job Exam", "সরকারি বা প্রতিযোগিতামূলক চাকরির পরীক্ষা", "analysis,writing,people", 3, 5, 1, 4, 5,
                "Stable if successful, but preparation is long and the result is uncertain.",
                "সফল হলে স্থিতিশীল, তবে প্রস্তুতি দীর্ঘ এবং ফল অনিশ্চিত।"),
            new Dest("lang", "Language Test (e.g. IELTS)", "ভাষা পরীক্ষা (যেমন আইইএলটিএস)", "writing,people", 3, 3, 2, 2, 2,
                "Opens study and work options abroad; needs regular practice in all four skills.",
                "বিদেশে পড়াশোনা ও কাজের সুযোগ খোলে; চার দক্ষতাতেই নিয়মিত অনুশীলন দরকার।"),
            new Dest("cert", "Professional Certification (IT, Finance)", "পেশাগত সার্টিফিকেশন (আইটি, ফাইন্যান্স)", "tech,analysis,business", 4, 3, 2, 2, 3,
                "Can strengthen a CV, but only if the employers you target value it.",
                "সিভি শক্তিশালী করতে পারে, তবে আপনার লক্ষ্যের নিয়োগকর্তারা মূল্য দিলে তবেই।")),
        "business", List.of(
            new Dest("freelance", "Freelance Service", "ফ্রিল্যান্স সার্ভিস", "tech,creative,writing", 3, 2, 4, 2, 2,
                "Low start-up cost, but income is uneven until you have reviews and repeat clients.",
                "শুরুর খরচ কম, তবে রিভিউ ও নিয়মিত ক্লায়েন্ট না হওয়া পর্যন্ত আয় অনিয়মিত।"),
            new Dest("ecom", "Online Product Business", "অনলাইন পণ্যের ব্যবসা", "business,hands,people", 4, 2, 3, 2, 3,
                "Needs capital for stock and you must handle delivery, returns and customer service.",
                "পণ্য কেনার মূলধন লাগে এবং ডেলিভারি, রিটার্ন ও কাস্টমার সার্ভিস সামলাতে হয়।"),
            new Dest("product", "Software Product or Startup", "সফটওয়্যার প্রোডাক্ট বা স্টার্টআপ", "tech,business,analysis", 5, 1, 4, 4, 5,
                "High upside but high risk; validate demand before building.",
                "সম্ভাবনা বেশি কিন্তু ঝুঁকিও বেশি; বানানোর আগে চাহিদা যাচাই করুন।"),
            new Dest("local", "Local Service Business", "স্থানীয় সেবা ব্যবসা", "people,hands", 3, 3, 2, 4, 3,
                "Customers are easier to understand, but growth is limited to your area at first.",
                "গ্রাহক বোঝা সহজ, তবে শুরুতে বৃদ্ধি আপনার এলাকায় সীমিত থাকে।")),
        "skills", List.of(
            new Dest("prog", "Programming", "প্রোগ্রামিং", "tech,analysis", 4, 3, 3, 3, 4,
                "Powerful, but needs weeks of practice before it feels rewarding.",
                "শক্তিশালী দক্ষতা, তবে ভালো লাগতে কয়েক সপ্তাহের অনুশীলন লাগে।"),
            new Dest("english", "English Communication", "ইংরেজি যোগাযোগ", "writing,people", 3, 4, 2, 3, 2,
                "Useful everywhere; progress is gradual and needs daily speaking and writing.",
                "সবখানে কাজে লাগে; উন্নতি ধীরে হয় এবং প্রতিদিন বলা ও লেখা দরকার।"),
            new Dest("design", "Design & Creative Skills", "ডিজাইন ও সৃজনশীল দক্ষতা", "creative", 3, 2, 5, 2, 2,
                "Enjoyable with visible results, but taste improves only through many iterations.",
                "আনন্দদায়ক ও ফল চোখে পড়ে, তবে রুচি গড়তে বহুবার চেষ্টা করতে হয়।"),
            new Dest("data", "Data & Spreadsheet Skills", "ডেটা ও স্প্রেডশিট দক্ষতা", "analysis,business", 3, 4, 1, 3, 2,
                "Quick to learn and widely useful; less visible unless you show projects.",
                "দ্রুত শেখা যায় ও বহুল ব্যবহৃত; প্রজেক্ট না দেখালে কম দৃশ্যমান।"),
            new Dest("habits", "Productivity & Habits", "প্রোডাক্টিভিটি ও অভ্যাস গঠন", "analysis,writing", 2, 4, 1, 3, 1,
                "Simple to start, but consistency is the real challenge.",
                "শুরু করা সহজ, কিন্তু ধারাবাহিকতা রাখাই আসল চ্যালেঞ্জ।")));

    static List<Map<String, Object>> opts(String[][] rows) {
        List<Map<String, Object>> l = new ArrayList<>();
        for (String[] r : rows) l.add(o("id", r[0], "name", bi(r[1], r[2])));
        return l;
    }
    static Map<String, Object> config() {
        Map<String, Object> tasks = new LinkedHashMap<>();
        TASKS.forEach((k, v) -> tasks.put(k, opts(v)));
        String[][] pri = {{"income", "Earning potential", "আয়ের সম্ভাবনা"}, {"stability", "Stability & security", "স্থিতিশীলতা ও নিরাপত্তা"},
            {"creativity", "Creative freedom", "সৃজনশীল স্বাধীনতা"}, {"impact", "Helping others / impact", "মানুষের উপকার / প্রভাব"}};
        String[][] hrs = {{"low", "Under 5 hours a week", "সপ্তাহে ৫ ঘণ্টার কম"}, {"mid", "5 to 12 hours a week", "সপ্তাহে ৫ থেকে ১২ ঘণ্টা"},
            {"high", "More than 12 hours a week", "সপ্তাহে ১২ ঘণ্টার বেশি"}};
        String[][] bud = {{"low", "Very limited", "খুবই সীমিত"}, {"mid", "Moderate", "মাঝারি"}, {"high", "Flexible", "নমনীয়"}};
        String[][] lvl = {{"beginner", "Beginner: starting from the basics", "শুরুর স্তর: একদম গোড়া থেকে"},
            {"intermediate", "Intermediate: I know the basics", "মাঝারি: মৌলিক বিষয় জানি"},
            {"advanced", "Advanced: I need polish and practice", "অগ্রসর: অনুশীলন ও পরিমার্জন দরকার"}};
        List<Map<String, Object>> qs = List.of(
            o("id", "interests", "type", "multi", "name", bi("What kinds of work interest you? (choose any)", "কোন ধরনের কাজ আপনার ভালো লাগে? (একাধিক বাছাই করুন)"), "options", opts(TAGS)),
            o("id", "priority", "type", "single", "name", bi("What matters most to you right now?", "এখন আপনার কাছে সবচেয়ে গুরুত্বপূর্ণ কী?"), "options", opts(pri)),
            o("id", "hours", "type", "single", "name", bi("How much time can you put in each week?", "প্রতি সপ্তাহে কত সময় দিতে পারবেন?"), "options", opts(hrs)),
            o("id", "budget", "type", "single", "name", bi("How flexible is your budget?", "আপনার বাজেট কতটা নমনীয়?"), "options", opts(bud)));
        List<Map<String, Object>> langs = Arrays.stream(LANGS)
                .map(l -> o("code", l[0], "name", l[1], "rtl", l[2].equals("rtl"))).collect(Collectors.toList());
        return o("domains", opts(DOMAINS), "tasks", tasks, "questions", qs, "levels", opts(lvl), "langs", langs);
    }

    // ===================================================================== RECOMMENDATION ENGINE (deterministic, explainable)
    static String tagName(String id, boolean bn) {
        for (String[] t : TAGS) if (t[0].equals(id)) return bn ? t[2] : t[1];
        return id;
    }
    static String pick(Map<String, String> f, String k, List<String> allowed, String def) {
        String v = f.get(k);
        if (v == null || v.isBlank()) return def;
        if (!allowed.contains(v)) throw bad();
        return v;
    }
    static Map<String, Object> recommend(Map<String, String> f) {
        String domain = f.getOrDefault("domain", "");
        List<Dest> dests = DESTS.get(domain);
        if (dests == null) throw bad();
        Set<String> valid = Arrays.stream(TAGS).map(t -> t[0]).collect(Collectors.toSet());
        Set<String> interests = new LinkedHashSet<>();
        String raw = f.getOrDefault("interests", "");
        if (!raw.isBlank()) for (String s : raw.split(",")) { if (!valid.contains(s)) throw bad(); interests.add(s); }
        String priority = pick(f, "priority", List.of("income", "stability", "creativity", "impact"), null);
        String hours = pick(f, "hours", List.of("low", "mid", "high"), null);
        String budget = pick(f, "budget", List.of("low", "mid", "high"), null);
        String style = pick(f, "style", List.of("structured", "flexible"), null);

        double cap = switch (hours == null ? "mid" : hours) { case "low" -> 2.0; case "high" -> 5.0; default -> 3.5; }
                + switch (budget == null ? "mid" : budget) { case "low" -> -0.5; case "high" -> 0.5; default -> 0.0; };

        List<Map<String, Object>> scored = new ArrayList<>();
        for (Dest d : dests) {
            Set<String> dt = new HashSet<>(Arrays.asList(d.tags().split(",")));
            List<String> matched = interests.stream().filter(dt::contains).collect(Collectors.toList());
            double interest = interests.isEmpty() ? 0.5 : (double) matched.size() / interests.size();
            double pri = priority == null ? 0.5 : (switch (priority) {
                case "income" -> d.inc(); case "stability" -> d.stab(); case "creativity" -> d.cre(); default -> d.imp(); }) / 5.0;
            double feas = 1 - Math.max(0, d.hard() - cap) / 5.0;
            double sty = style == null ? 0.5 : (style.equals("structured") ? d.stab() : d.cre()) / 5.0;
            double fit = 100 * (0.40 * interest + 0.30 * pri + 0.20 * feas + 0.10 * sty);

            List<String> reasons = new ArrayList<>();
            if (!matched.isEmpty())
                reasons.add(bi("Matches your interests: " + matched.stream().map(x -> tagName(x, false)).collect(Collectors.joining(", ")),
                        "আপনার আগ্রহের সাথে মেলে: " + matched.stream().map(x -> tagName(x, true)).collect(Collectors.joining(", "))));
            else if (!interests.isEmpty())
                reasons.add(bi("Little overlap with the interests you selected.", "আপনার বাছাই করা আগ্রহের সাথে মিল কম।"));
            if (priority != null) {
                int v = switch (priority) { case "income" -> d.inc(); case "stability" -> d.stab(); case "creativity" -> d.cre(); default -> d.imp(); };
                reasons.add(v >= 4 ? bi("Strongly aligned with what matters most to you.", "আপনার সবচেয়ে গুরুত্বপূর্ণ বিষয়ের সাথে ভালোভাবে মেলে।")
                        : v == 3 ? bi("Partly aligned with what matters most to you.", "আপনার সবচেয়ে গুরুত্বপূর্ণ বিষয়ের সাথে আংশিক মেলে।")
                        : bi("Weaker match for what matters most to you.", "আপনার সবচেয়ে গুরুত্বপূর্ণ বিষয়ের সাথে মিল কম।"));
            }
            reasons.add(d.hard() <= cap ? bi("Realistic with the time and budget you described.", "আপনার দেওয়া সময় ও বাজেটে বাস্তবসম্মত।")
                    : bi("Demands more time or resources than you described; needs a longer timeline.", "আপনার দেওয়া সময় বা সম্পদের চেয়ে বেশি লাগবে; দীর্ঘ সময়সীমা দরকার।"));

            scored.add(o("id", d.id(), "name", bi(d.en(), d.bn()), "fit", (int) Math.round(fit),
                    "reasons", reasons, "tradeoff", bi(d.tEn(), d.tBn())));
        }
        scored.sort((a, b) -> (int) b.get("fit") - (int) a.get("fit"));

        int answered = (interests.isEmpty() ? 0 : 1) + (priority != null ? 1 : 0) + (hours != null ? 1 : 0) + (budget != null ? 1 : 0) + (style != null ? 1 : 0);
        String conf = answered >= 5 ? bi("Fair", "মোটামুটি") : answered >= 3 ? bi("Moderate", "মাঝারি") : bi("Low", "কম");
        List<String> assumptions = new ArrayList<>();
        if (hours == null) assumptions.add(bi("Assumed 5 to 12 hours a week.", "ধরে নেওয়া হয়েছে সপ্তাহে ৫ থেকে ১২ ঘণ্টা।"));
        if (budget == null) assumptions.add(bi("Assumed a moderate budget.", "ধরে নেওয়া হয়েছে মাঝারি বাজেট।"));
        if (priority == null) assumptions.add(bi("No main priority given, so all priorities were weighted equally.", "প্রধান অগ্রাধিকার দেওয়া হয়নি, তাই সব অগ্রাধিকারকে সমান ধরা হয়েছে।"));
        List<String> unknowns = List.of(
            bi("Your actual results, grades and eligibility are not known.", "আপনার প্রকৃত ফলাফল, গ্রেড ও যোগ্যতা জানা নেই।"),
            bi("Costs, deadlines and requirements change; verify them on official websites.", "খরচ, সময়সীমা ও শর্ত বদলায়; অফিসিয়াল ওয়েবসাইটে যাচাই করুন।"),
            bi("This is a short-questionnaire estimate, not a full assessment. Talk to a counsellor or mentor for big decisions.", "এটি ছোট প্রশ্নমালার ভিত্তিতে অনুমান, পূর্ণ মূল্যায়ন নয়। বড় সিদ্ধান্তে কাউন্সেলর বা মেন্টরের সাথে কথা বলুন।"));

        Map<String, Object> out = o("results", scored, "confidence", conf, "assumptions", assumptions, "unknowns", unknowns,
                "note", bi("Fit scores are rough estimates from the questions you answered, using simple general assumptions, not market data.",
                        "ফিট স্কোর আপনার উত্তরের ভিত্তিতে সাধারণ ধারণা থেকে করা মোটামুটি অনুমান, বাজারের তথ্য নয়।"));
        if (style == null && scored.size() > 1 && (int) scored.get(0).get("fit") - (int) scored.get(1).get("fit") <= 5) {
            out.put("followup", o("id", "style", "type", "single",
                    "name", bi("The top options are very close. Which work style suits you better?", "শীর্ষ বিকল্পগুলো খুব কাছাকাছি। কোন কাজের ধরন আপনার বেশি পছন্দ?"),
                    "options", List.of(o("id", "structured", "name", bi("Structured and predictable", "কাঠামোবদ্ধ ও অনুমানযোগ্য")),
                            o("id", "flexible", "name", bi("Flexible and creative", "নমনীয় ও সৃজনশীল")))));
        }
        return out;
    }

    // ===================================================================== ROADMAP ENGINE
    static String[] r(String ph, String id, String te, String tb, String ve, String vb) { return new String[]{ph, id, te, tb, ve, vb}; }
    static final Map<String, String[][]> ROAD = Map.of(
        "education", new String[][]{
            r("F", "F1", "Collect the official requirements (syllabus, course list, deadlines) from the institution's website",
                "প্রতিষ্ঠানের ওয়েবসাইট থেকে অফিসিয়াল শর্ত (সিলেবাস, কোর্স তালিকা, সময়সীমা) সংগ্রহ করুন",
                "You have a one-page requirements list with source links.", "সূত্রসহ এক পাতার একটি শর্ত-তালিকা আপনার হাতে আছে।"),
            r("F", "F2", "Revise the prerequisite basics (maths, English, computer fundamentals as relevant)",
                "পূর্বশর্ত মৌলিক বিষয়গুলো ঝালাই করুন (প্রাসঙ্গিক হলে গণিত, ইংরেজি, কম্পিউটার বেসিক)",
                "You score 70% or more on a self-made 20-question quiz.", "নিজের বানানো ২০ প্রশ্নের কুইজে ৭০% বা বেশি পান।"),
            r("C", "C1", "Study the introductory material of your first-term core subjects",
                "প্রথম টার্মের মূল বিষয়গুলোর শুরুর অংশ পড়ুন",
                "You can explain each main topic aloud in 3 minutes.", "প্রতিটি মূল বিষয় ৩ মিনিটে মুখে ব্যাখ্যা করতে পারেন।"),
            r("C", "C2", "Set up your study system: weekly timetable, note-taking method, and someone to ask questions",
                "পড়ার ব্যবস্থা সাজান: সাপ্তাহিক রুটিন, নোট নেওয়ার পদ্ধতি এবং প্রশ্ন করার মতো কেউ",
                "A weekly timetable exists and you followed it for 7 days.", "সাপ্তাহিক রুটিন তৈরি আছে এবং টানা ৭ দিন মেনেছেন।"),
            r("P", "P1", "Solve sample problems or small assignments every week",
                "প্রতি সপ্তাহে নমুনা সমস্যা বা ছোট অ্যাসাইনমেন্ট সমাধান করুন",
                "10 solved problems with your mistakes logged.", "১০টি সমাধান করা সমস্যা এবং ভুলগুলোর তালিকা।"),
            r("P", "P2", "Talk to two seniors or alumni about the real workload and expectations",
                "দুজন সিনিয়র বা প্রাক্তন শিক্ষার্থীর সাথে আসল পড়ার চাপ ও প্রত্যাশা নিয়ে কথা বলুন",
                "You wrote down 5 insights and adjusted your plan.", "৫টি শিক্ষা লিখেছেন এবং পরিকল্পনা সামঞ্জস্য করেছেন।")},
        "career", new String[][]{
            r("F", "F1", "Pick one target role and read 10 real job descriptions",
                "একটি লক্ষ্য পদ বেছে নিন এবং ১০টি আসল চাকরির বিজ্ঞপ্তি পড়ুন",
                "A list of the 8 most repeated requirements.", "সবচেয়ে বেশি পুনরাবৃত্ত ৮টি শর্তের তালিকা।"),
            r("F", "F2", "Learn the basics of the most repeated requirement",
                "সবচেয়ে বেশি চাওয়া দক্ষতার মৌলিক অংশ শিখুন",
                "You finished a beginner module and a small exercise.", "একটি শুরুর মডিউল ও ছোট অনুশীলন শেষ করেছেন।"),
            r("C", "C1", "Build the top 3 required skills through weekly practice",
                "সবচেয়ে প্রয়োজনীয় ৩টি দক্ষতা সাপ্তাহিক অনুশীলনে গড়ে তুলুন",
                "Each of the 3 skills is shown by a small work sample.", "৩টি দক্ষতার প্রতিটির একটি করে ছোট কাজের নমুনা আছে।"),
            r("C", "C2", "Draft your CV and an online professional profile",
                "আপনার সিভি ও অনলাইন পেশাদার প্রোফাইলের খসড়া করুন",
                "A one-page CV reviewed by one person in the field.", "ক্ষেত্রটির একজন মানুষ দেখেছেন এমন এক পাতার সিভি।"),
            r("P", "P1", "Complete two portfolio projects or work samples",
                "দুটি পোর্টফোলিও প্রজেক্ট বা কাজের নমুনা শেষ করুন",
                "Both are shareable with a short write-up.", "দুটিই ছোট বিবরণসহ শেয়ার করার মতো অবস্থায় আছে।"),
            r("P", "P2", "Practise interviews: five mock interviews or recorded answers",
                "ইন্টারভিউ অনুশীলন করুন: পাঁচটি মক ইন্টারভিউ বা রেকর্ড করা উত্তর",
                "You can answer 10 common questions in under 2 minutes each.", "১০টি সাধারণ প্রশ্নের প্রতিটির উত্তর ২ মিনিটের মধ্যে দিতে পারেন।")},
        "exams", new String[][]{
            r("F", "F1", "Get the official syllabus, exam pattern and dates",
                "অফিসিয়াল সিলেবাস, পরীক্ষার কাঠামো ও তারিখ সংগ্রহ করুন",
                "A checklist with every syllabus topic listed.", "সিলেবাসের প্রতিটি টপিকসহ একটি চেকলিস্ট।"),
            r("F", "F2", "Take a diagnostic test and mark your weak topics",
                "একটি ডায়াগনস্টিক টেস্ট দিন এবং দুর্বল টপিক চিহ্নিত করুন",
                "A ranked list of weak topics with scores.", "স্কোরসহ দুর্বল টপিকের একটি ক্রমতালিকা।"),
            r("C", "C1", "Study weak topics first, then the rest, in spaced sessions",
                "আগে দুর্বল টপিক, তারপর বাকিগুলো থেমে থেমে পড়ুন",
                "Each topic has notes and 70% or more on its quiz.", "প্রতিটি টপিকের নোট আছে এবং কুইজে ৭০% বা বেশি পেয়েছেন।"),
            r("C", "C2", "Create a revision calendar with a weekly review slot",
                "সাপ্তাহিক রিভিশনের সময়সহ একটি রিভিশন ক্যালেন্ডার বানান",
                "The calendar covers every week until the exam date.", "ক্যালেন্ডার পরীক্ষার তারিখ পর্যন্ত প্রতিটি সপ্তাহ ঢেকে আছে।"),
            r("P", "P1", "Solve timed past papers every week",
                "প্রতি সপ্তাহে সময় ধরে আগের বছরের প্রশ্ন সমাধান করুন",
                "Papers are scored and your error log is updated.", "প্রশ্নগুলোর স্কোর করা হয়েছে এবং ভুলের তালিকা হালনাগাদ।"),
            r("P", "P2", "Practise the exam-day routine: timing, strategy and rest",
                "পরীক্ষার দিনের রুটিন অনুশীলন করুন: সময় ব্যবস্থাপনা, কৌশল ও বিশ্রাম",
                "You completed one full mock under exam conditions.", "পরীক্ষার মতো পরিবেশে একটি পূর্ণ মক শেষ করেছেন।")},
        "business", new String[][]{
            r("F", "F1", "Write the problem, target customer and your assumptions on one page",
                "সমস্যা, লক্ষ্য গ্রাহক ও আপনার ধারণাগুলো এক পাতায় লিখুন",
                "A one-page canvas naming the 3 riskiest assumptions.", "সবচেয়ে ঝুঁকিপূর্ণ ৩টি ধারণাসহ এক পাতার ক্যানভাস।"),
            r("F", "F2", "Research competitors and prices from real sources",
                "আসল সূত্র থেকে প্রতিযোগী ও দাম নিয়ে গবেষণা করুন",
                "A table of 5 competitors with price and gap.", "দাম ও ফাঁকসহ ৫ প্রতিযোগীর একটি ছক।"),
            r("C", "C1", "Interview 10 potential customers",
                "১০ জন সম্ভাব্য গ্রাহকের সাক্ষাৎকার নিন",
                "Notes from 10 conversations with patterns summarised.", "১০টি কথোপকথনের নোট ও প্রধান প্যাটার্নের সারাংশ।"),
            r("C", "C2", "Define the smallest first version (MVP) and its cost",
                "সবচেয়ে ছোট প্রথম সংস্করণ (এমভিপি) ও তার খরচ ঠিক করুন",
                "An MVP scope of at most 5 features with a budget.", "সর্বোচ্চ ৫টি ফিচার ও বাজেটসহ এমভিপির পরিধি।"),
            r("P", "P1", "Run a low-cost test: pre-orders, a landing page or a small pilot",
                "কম খরচে পরীক্ষা চালান: প্রি-অর্ডার, ল্যান্ডিং পেজ বা ছোট পাইলট",
                "You compared the number of commitments with a target set beforehand.", "আগে ঠিক করা লক্ষ্যের সাথে প্রতিশ্রুতির সংখ্যা তুলনা করেছেন।"),
            r("P", "P2", "Track money and decide: continue, change or stop",
                "টাকার হিসাব রাখুন এবং সিদ্ধান্ত নিন: চালিয়ে যাবেন, বদলাবেন, নাকি থামবেন",
                "A simple cost and income sheet and a written decision.", "সহজ আয়-ব্যয়ের ছক এবং লিখিত সিদ্ধান্ত।")},
        "skills", new String[][]{
            r("F", "F1", "Define a concrete end result: something you can show",
                "একটি নির্দিষ্ট ফলাফল ঠিক করুন: যা আপনি দেখাতে পারবেন",
                "A one-sentence project statement with a finish date.", "শেষ করার তারিখসহ এক বাক্যের প্রজেক্ট বিবরণ।"),
            r("F", "F2", "Choose one main learning resource and stick to it",
                "একটি প্রধান শেখার উৎস বেছে নিন এবং তাতেই থাকুন",
                "The resource is chosen and its first module completed.", "উৎস বাছাই হয়েছে এবং প্রথম মডিউল শেষ।"),
            r("C", "C1", "Practise in short daily sessions and keep a log",
                "প্রতিদিন অল্প সময় অনুশীলন করুন এবং একটি লগ রাখুন",
                "At least 5 days a week logged for 2 weeks.", "২ সপ্তাহ ধরে সপ্তাহে অন্তত ৫ দিন লগ করা।"),
            r("C", "C2", "Learn by building: apply each concept in a mini-task",
                "বানিয়ে শিখুন: প্রতিটি ধারণা ছোট একটি কাজে প্রয়োগ করুন",
                "5 mini-tasks completed.", "৫টি ছোট কাজ সম্পন্ন।"),
            r("P", "P1", "Build the final project",
                "চূড়ান্ত প্রজেক্টটি বানান",
                "The project works and you showed it to someone.", "প্রজেক্টটি কাজ করে এবং কাউকে দেখিয়েছেন।"),
            r("P", "P2", "Get feedback and fix the top 3 issues",
                "মতামত নিন এবং সবচেয়ে বড় ৩টি সমস্যা ঠিক করুন",
                "Feedback received and 3 changes made.", "মতামত পেয়েছেন এবং ৩টি পরিবর্তন করেছেন।")});

    static final String[][] REVIEW = {
        r("R", "R1", "Checkpoint: compare your progress with the milestones and adjust the plan",
            "চেকপয়েন্ট: অগ্রগতিকে মাইলফলকের সাথে মিলিয়ে পরিকল্পনা সামঞ্জস্য করুন",
            "A written note: what is on track, what is late, and why.", "একটি লিখিত নোট: কী ঠিক আছে, কী পিছিয়ে, এবং কেন।"),
        r("R", "R2", "Decide the next step: continue, narrow the scope, or reconsider the destination",
            "পরের ধাপ ঠিক করুন: চালিয়ে যাবেন, পরিধি কমাবেন, নাকি গন্তব্য নতুন করে ভাববেন",
            "A decision with a reason you can explain.", "ব্যাখ্যা করার মতো কারণসহ একটি সিদ্ধান্ত।")};

    static final Map<String, String[]> PHASES = Map.of(
        "F", new String[]{"Phase 1: Foundations", "ধাপ ১: ভিত্তি",
            "Gaps in the basics slow down everything after them, so they are closed first.", "ভিত্তিতে ফাঁক থাকলে পরের সবকিছু ধীর হয়, তাই আগে সেটি পূরণ করা হয়।",
            "Short daily sessions, notes in your own words, and self-testing without looking.", "প্রতিদিন অল্প সময়, নিজের ভাষায় নোট এবং না দেখে নিজেকে যাচাই।"},
        "C", new String[]{"Phase 2: Core skills", "ধাপ ২: মূল দক্ষতা",
            "These skills are what your destination actually demands.", "আপনার গন্তব্য আসলে এই দক্ষতাগুলোই চায়।",
            "Learn a concept, apply it the same day, and record what you got wrong.", "একটি ধারণা শিখে একই দিনে প্রয়োগ করুন এবং কোথায় ভুল হলো তা লিখে রাখুন।"},
        "P", new String[]{"Phase 3: Practice and deliverables", "ধাপ ৩: অনুশীলন ও ফলাফল",
            "Real practice and visible results show whether you are ready.", "বাস্তব অনুশীলন ও দৃশ্যমান ফল দেখায় আপনি প্রস্তুত কি না।",
            "Work under realistic conditions and ask someone for honest feedback.", "বাস্তবসম্মত পরিস্থিতিতে কাজ করুন এবং কারও কাছ থেকে সৎ মতামত নিন।"},
        "R", new String[]{"Phase 4: Review and next step", "ধাপ ৪: পর্যালোচনা ও পরবর্তী ধাপ",
            "Plans need checking against reality. Slow progress is information, not failure.", "পরিকল্পনা বাস্তবতার সাথে মেলানো দরকার। ধীর অগ্রগতি তথ্য, ব্যর্থতা নয়।",
            "Review your logs, scores and notes, then change the plan deliberately.", "লগ, স্কোর ও নোট দেখে ভেবেচিন্তে পরিকল্পনা বদলান।"});

    static List<String[]> rowsFor(Goal g) {
        boolean compact = g.weeks() <= 3;
        List<String[]> rows = new ArrayList<>();
        List<String[]> all = new ArrayList<>(Arrays.asList(ROAD.get(g.domain())));
        all.addAll(Arrays.asList(REVIEW));
        Set<String> seenPhase = new HashSet<>();
        for (String[] row : all) {
            if (!g.level().equals("beginner") && row[0].equals("F")) continue; // foundations are for beginners only
            if (compact && !seenPhase.add(row[0])) continue;                  // 3 weeks or less: first task per phase
            rows.add(row);
        }
        return rows;
    }
    static Map<String, Object> roadmap(Goal g) {
        String lvl = g.level();
        String[] ph; double[] frac;
        if (lvl.equals("beginner")) { ph = new String[]{"F", "C", "P", "R"}; frac = new double[]{.25, .35, .30, .10}; }
        else if (lvl.equals("intermediate")) { ph = new String[]{"C", "P", "R"}; frac = new double[]{.40, .45, .15}; }
        else { ph = new String[]{"C", "P", "R"}; frac = new double[]{.25, .60, .15}; }

        int W = g.weeks(), H = g.hours();
        double avail = (double) W * H;
        int required = lvl.equals("beginner") ? 120 : lvl.equals("intermediate") ? 70 : 40;
        double ratio = avail / required;
        String status = ratio >= 1 ? "realistic" : ratio >= 0.6 ? "tight" : "unrealistic";
        int weeksNeeded = (int) Math.ceil((double) required / H), hoursNeeded = (int) Math.ceil((double) required / W);
        String msgEn, msgBn;
        if (status.equals("realistic")) {
            msgEn = "Your time budget (" + (int) avail + " hours) looks sufficient for this plan, based on a rough estimate of about " + required + " hours.";
            msgBn = "আপনার সময় (" + bnDigits("" + (int) avail) + " ঘণ্টা) এই পরিকল্পনার জন্য যথেষ্ট মনে হচ্ছে; মোটামুটি অনুমান প্রায় " + bnDigits("" + required) + " ঘণ্টা।";
        } else if (status.equals("tight")) {
            msgEn = "Tight: you have about " + (int) avail + " hours against a rough estimate of " + required + ". It is possible with consistent effort, but there is little slack.";
            msgBn = "সময় কম: আপনার হাতে প্রায় " + bnDigits("" + (int) avail) + " ঘণ্টা, অনুমান প্রায় " + bnDigits("" + required) + " ঘণ্টা। নিয়মিত পরিশ্রমে সম্ভব, কিন্তু বাড়তি সময় প্রায় নেই।";
        } else {
            msgEn = "Not enough time for the full plan: about " + (int) avail + " hours against a rough estimate of " + required + ". Options: extend to about " + weeksNeeded
                    + " weeks, raise weekly hours to about " + hoursNeeded + ", or narrow the scope and focus on the essential tasks.";
            msgBn = "পূর্ণ পরিকল্পনার জন্য সময় যথেষ্ট নয়: প্রায় " + bnDigits("" + (int) avail) + " ঘণ্টা, অনুমান প্রায় " + bnDigits("" + required) + " ঘণ্টা। বিকল্প: প্রায় "
                    + bnDigits("" + weeksNeeded) + " সপ্তাহে বাড়ান, সাপ্তাহিক ঘণ্টা প্রায় " + bnDigits("" + hoursNeeded) + " করুন, অথবা পরিধি কমিয়ে জরুরি কাজে মনোযোগ দিন।";
        }
        if (W <= 3) {
            msgEn += " With 3 weeks or less, only the first task of each phase is included.";
            msgBn += " ৩ সপ্তাহ বা তার কম হলে প্রতিটি ধাপের শুধু প্রথম কাজটি রাখা হয়েছে।";
        }

        Set<String> done = new HashSet<>(Arrays.asList(g.done().split(",")));
        List<String[]> rows = rowsFor(g);
        List<Map<String, Object>> phases = new ArrayList<>();
        int total = 0, doneCount = 0; double cum = 0;
        for (int i = 0; i < ph.length; i++) {
            final String pid = ph[i];
            List<String[]> pr = rows.stream().filter(x -> x[0].equals(pid)).collect(Collectors.toList());
            int start = (int) Math.floor(cum * W) + 1;
            cum += frac[i];
            int end = Math.max(start, (int) Math.ceil(cum * W));
            start = Math.min(start, W); end = Math.min(end, W);
            String[] meta = PHASES.get(pid);
            List<Map<String, Object>> tasks = new ArrayList<>();
            for (String[] row : pr) {
                boolean d = done.contains(row[1]);
                total++; if (d) doneCount++;
                int hrs = (int) Math.max(1, Math.round(avail * frac[i] / pr.size()));
                tasks.add(o("id", row[1], "title", bi(row[2], row[3]), "verify", bi(row[4], row[5]), "hours", hrs, "done", d));
            }
            String wEn = start == end ? "Week " + start : "Weeks " + start + "-" + end;
            String wBn = start == end ? "সপ্তাহ " + bnDigits("" + start) : "সপ্তাহ " + bnDigits(start + "-" + end);
            phases.add(o("id", pid, "title", bi(meta[0], meta[1]), "why", bi(meta[2], meta[3]), "how", bi(meta[4], meta[5]),
                    "weeks", bi(wEn, wBn), "tasks", tasks));
        }
        List<String> assumptions = List.of(
            bi("Starting level: " + lvl + ". Time: " + W + " weeks at about " + H + " hours a week.",
               "শুরুর স্তর: " + lvl + "। সময়: " + bnDigits("" + W) + " সপ্তাহ, সপ্তাহে প্রায় " + bnDigits("" + H) + " ঘণ্টা।"),
            bi("Hour estimates are rough planning guides and will differ for each person.", "ঘণ্টার হিসাব মোটামুটি পরিকল্পনার নির্দেশনা; প্রত্যেকের ক্ষেত্রে আলাদা হবে।"),
            bi("Requirements, dates and fees are not included here. Verify them from official sources before acting.", "শর্ত, তারিখ ও ফি এখানে দেওয়া নেই। কাজ শুরুর আগে অফিসিয়াল সূত্রে যাচাই করুন।"));
        int pct = total == 0 ? 0 : (int) Math.round(100.0 * doneCount / total);
        return o("title", g.title(),
                "success", bi("Success means you can show the check-result for every milestone by week " + W + ". This plan supports your preparation; it cannot guarantee admission, a job or business results.",
                        "সফলতা মানে সপ্তাহ " + bnDigits("" + W) + "-এর মধ্যে প্রতিটি মাইলফলকের যাচাই-ফল দেখাতে পারা। এই পরিকল্পনা আপনার প্রস্তুতিতে সাহায্য করে; ভর্তি, চাকরি বা ব্যবসার সাফল্যের নিশ্চয়তা দেয় না।"),
                "feasibility", o("status", status, "message", bi(msgEn, msgBn)),
                "assumptions", assumptions, "phases", phases,
                "progress", o("done", doneCount, "total", total, "percent", pct));
    }
    static Map<String, Object> goalJson(Goal g) {
        Map<String, Object> rm = roadmap(g);
        return o("id", g.id(), "title", g.title(), "domain", g.domain(), "task", g.task(), "level", g.level(),
                "weeks", g.weeks(), "hours", g.hours(), "created", g.created(), "progress", rm.get("progress"));
    }

    // ===================================================================== HTTP LAYER
    static Map<String, String> form(HttpExchange ex) throws IOException {
        byte[] b = ex.getRequestBody().readNBytes(20_001);
        if (b.length > 20_000) throw new ApiError(413, "Request too large.||অনুরোধ অনেক বড়।");
        Map<String, String> m = new HashMap<>();
        String s = new String(b, StandardCharsets.UTF_8);
        if (s.isBlank()) return m;
        for (String p : s.split("&")) {
            String[] kv = p.split("=", 2);
            m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return m;
    }
    static void sendRaw(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        h.set("Cache-Control", "no-store");
        h.set("X-Content-Type-Options", "nosniff");
        h.set("X-Frame-Options", "DENY");
        h.set("Referrer-Policy", "same-origin");
        h.set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
    static void sendJson(HttpExchange ex, int status, Object v) throws IOException { sendRaw(ex, status, "application/json; charset=utf-8", json(v)); }

    static String text(Map<String, String> f, String k, int min, int max) {
        String v = f.getOrDefault(k, "").trim();
        if (v.length() < min || v.length() > max) throw bad();
        return v;
    }
    static int num(Map<String, String> f, String k, int min, int max) {
        try { int v = Integer.parseInt(f.getOrDefault(k, "").trim()); if (v < min || v > max) throw bad(); return v; }
        catch (NumberFormatException e) { throw bad(); }
    }

    static void route(HttpExchange ex) throws Exception {
        String path = ex.getRequestURI().getPath(), m = ex.getRequestMethod();
        if (m.equals("GET")) {
            switch (path) {
                case "/", "/index.html" -> { sendRaw(ex, 200, "text/html; charset=utf-8", HTML); return; }
                case "/app.js" -> { sendRaw(ex, 200, "text/javascript; charset=utf-8", JS); return; }
                case "/app.css" -> { sendRaw(ex, 200, "text/css; charset=utf-8", CSS); return; }
                case "/healthz" -> { sendRaw(ex, 200, "text/plain", "ok"); return; }
                default -> { }
            }
        }
        if (!path.startsWith("/api/")) throw new ApiError(404, "Not found.||পাওয়া যায়নি।");
        if (!m.equals("GET") && !"fetch".equals(ex.getRequestHeaders().getFirst("X-Requested-With")))
            throw new ApiError(403, "Blocked request.||অনুরোধ আটকানো হয়েছে।");
        Map<String, String> f = m.equals("POST") ? form(ex) : Map.of();
        String ip = ex.getRemoteAddress().getAddress().getHostAddress();

        switch (m + " " + path) {
            case "GET /api/config" -> { sendJson(ex, 200, config()); return; }
            case "GET /api/me" -> { User u = currentUser(ex); sendJson(ex, 200, o("user", u == null ? null : pub(u))); return; }
            case "POST /api/signup" -> {
                rateCheck("signup|" + ip, 10, 3600_000);
                String name = text(f, "name", 2, 60), email = text(f, "email", 3, 254).toLowerCase(Locale.ROOT), pw = f.getOrDefault("password", "");
                if (!EMAIL.matcher(email).matches()) throw new ApiError(400, "Enter a valid email address.||সঠিক ইমেইল ঠিকানা দিন।");
                if (pw.length() < 8 || pw.length() > 128) throw new ApiError(400, "Password must be 8 to 128 characters.||পাসওয়ার্ড ৮ থেকে ১২৮ অক্ষরের হতে হবে।");
                rateHit("signup|" + ip);
                byte[] salt = new byte[16]; RNG.nextBytes(salt);
                User u = store.addUser(email, name, B64.encodeToString(salt), hashPw(pw, salt));
                startSession(ex, u.id());
                sendJson(ex, 201, o("user", pub(u))); return;
            }
            case "POST /api/login" -> {
                String email = f.getOrDefault("email", "").trim().toLowerCase(Locale.ROOT), pw = f.getOrDefault("password", "");
                String key = "login|" + ip + "|" + email;
                rateCheck(key, 5, 600_000);
                User u = store.byEmail(email);
                byte[] salt = u == null ? DUMMY_SALT : Base64.getDecoder().decode(u.salt());
                String h = hashPw(pw, salt);
                if (u == null || !MessageDigest.isEqual(h.getBytes(StandardCharsets.UTF_8), u.hash().getBytes(StandardCharsets.UTF_8))) {
                    rateHit(key);
                    throw new ApiError(401, "Incorrect email or password.||ইমেইল বা পাসওয়ার্ড ভুল।");
                }
                startSession(ex, u.id());
                sendJson(ex, 200, o("user", pub(u))); return;
            }
            case "POST /api/logout" -> {
                String tok = sessionToken(ex);
                if (tok != null) SESSIONS.remove(tok);
                cookie(ex, "", 0);
                sendJson(ex, 200, o("ok", true)); return;
            }
            case "POST /api/recommend" -> { sendJson(ex, 200, recommend(f)); return; }
            case "GET /api/goals" -> {
                User u = need(ex);
                sendJson(ex, 200, o("goals", store.goalsOf(u.id()).stream().map(DestinationAI::goalJson).collect(Collectors.toList()))); return;
            }
            case "POST /api/goals" -> {
                User u = need(ex);
                String domain = f.getOrDefault("domain", "");
                if (!TASKS.containsKey(domain)) throw bad();
                String task = f.getOrDefault("task", "");
                if (Arrays.stream(TASKS.get(domain)).noneMatch(t -> t[0].equals(task))) throw bad();
                String level = f.getOrDefault("level", "");
                if (!List.of("beginner", "intermediate", "advanced").contains(level)) throw bad();
                if (store.goalsOf(u.id()).size() >= 50) throw new ApiError(400, "Plan limit reached (50).||পরিকল্পনার সীমা (৫০) শেষ।");
                Goal g = new Goal(rid(), u.id(), domain, task, text(f, "title", 3, 120), level, num(f, "weeks", 1, 104), num(f, "hours", 1, 80), System.currentTimeMillis(), "");
                store.putGoal(g);
                sendJson(ex, 201, o("id", g.id())); return;
            }
            case "POST /api/account/delete" -> {
                User u = need(ex);
                String h = hashPw(f.getOrDefault("password", ""), Base64.getDecoder().decode(u.salt()));
                if (!MessageDigest.isEqual(h.getBytes(StandardCharsets.UTF_8), u.hash().getBytes(StandardCharsets.UTF_8)))
                    throw new ApiError(403, "Incorrect password.||পাসওয়ার্ড ভুল।");
                store.deleteUser(u.id());
                SESSIONS.values().removeIf(s -> s.userId().equals(u.id()));
                cookie(ex, "", 0);
                sendJson(ex, 200, o("ok", true)); return;
            }
            case "GET /api/export" -> {
                User u = need(ex);
                List<Map<String, Object>> gs = store.goalsOf(u.id()).stream()
                        .map(g -> o("title", g.title(), "domain", g.domain(), "task", g.task(), "level", g.level(), "weeks", g.weeks(),
                                "hoursPerWeek", g.hours(), "created", g.created(), "completedTasks", g.done().isEmpty() ? List.of() : Arrays.asList(g.done().split(","))))
                        .collect(Collectors.toList());
                sendJson(ex, 200, o("user", pub(u), "plans", gs)); return;
            }
            default -> { }
        }

        // /api/lang/{code}  -> translation pack for one language (empty object if no pack file exists)
        if (m.equals("GET") && path.startsWith("/api/lang/")) { sendJson(ex, 200, langPack(path.substring("/api/lang/".length()))); return; }

        // /api/goals/{id}[/toggle|/delete]
        if (path.startsWith("/api/goals/")) {
            User u = need(ex);
            String[] p = path.substring("/api/goals/".length()).split("/");
            Goal g = store.goal(p[0], u.id());
            if (p.length == 1 && m.equals("GET")) { sendJson(ex, 200, o("goal", goalJson(g), "roadmap", roadmap(g))); return; }
            if (p.length == 2 && m.equals("POST") && p[1].equals("delete")) { store.removeGoal(g.id()); sendJson(ex, 200, o("ok", true)); return; }
            if (p.length == 2 && m.equals("POST") && p[1].equals("toggle")) {
                String tid = f.getOrDefault("task", "");
                if (rowsFor(g).stream().noneMatch(r -> r[1].equals(tid))) throw bad();
                Set<String> done = new LinkedHashSet<>();
                if (!g.done().isEmpty()) done.addAll(Arrays.asList(g.done().split(",")));
                if (!done.remove(tid)) done.add(tid);
                Goal ng = new Goal(g.id(), g.userId(), g.domain(), g.task(), g.title(), g.level(), g.weeks(), g.hours(), g.created(), String.join(",", done));
                store.putGoal(ng);
                sendJson(ex, 200, o("goal", goalJson(ng), "roadmap", roadmap(ng))); return;
            }
        }
        throw new ApiError(404, "Not found.||পাওয়া যায়নি।");
    }

    public static void main(String[] args) throws Exception {
        store = new Store(DATA_DIR);
        HttpServer server = HttpServer.create(new InetSocketAddress(HOST, PORT), 0);
        server.createContext("/", ex -> {
            try { route(ex); }
            catch (ApiError e) { try { sendJson(ex, e.status, o("error", e.getMessage())); } catch (IOException ignored) { } }
            catch (Exception e) {
                e.printStackTrace();
                try { sendJson(ex, 500, o("error", "Server error. Please try again.||সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন।")); } catch (IOException ignored) { }
            } finally { ex.close(); }
        });
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor(rn -> { Thread t = new Thread(rn); t.setDaemon(true); return t; });
        cleaner.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            SESSIONS.values().removeIf(s -> s.expires() < now);
            ATTEMPTS.entrySet().removeIf(e -> { synchronized (e.getValue()) { return e.getValue().isEmpty() || now - e.getValue().peekLast() > 3600_000; } });
        }, 10, 10, TimeUnit.MINUTES);
        server.start();
        System.out.println("Destination AI running at http://" + (HOST.equals("0.0.0.0") ? "localhost" : HOST) + ":" + PORT + "  (data in ./" + DATA_DIR + ")");
        System.out.println("Languages: " + LANGS.length + " selectable; packs in ./" + DATA_DIR.resolve("lang"));
    }

    // ===================================================================== FRONTEND: HTML
    static final String HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Destination AI</title>
<meta name="description" content="Discover the right direction and follow a personalised, realistic roadmap. 50 languages.">
<link rel="stylesheet" href="/app.css">
</head>
<body>
<a class="skip" href="#app">Skip to content</a>
<div id="root"></div>
<noscript>Destination AI needs JavaScript to run.</noscript>
<script src="/app.js"></script>
</body>
</html>
""";

    // ===================================================================== FRONTEND: CSS ("Compass" theme)
    static final String CSS = """
:root{--bg:#f5efe3;--paper:#fffcf5;--ink:#1d1b2f;--mut:#645f73;--pri:#0d5c63;--pri2:#083f45;--onpri:#fff;--acc:#e8a33d;--night:#1d1b2f;--ok:#1f6b3a;--okbg:#e3f1e2;--warn:#8a5200;--warnbg:#fdecc8;--bad:#9d2b2b;--badbg:#f9dcd6;--info:#0d5c63;--infobg:#dcefee;--line:#e4d9c3;--r:18px}
@media(prefers-color-scheme:dark){:root{--bg:#14121f;--paper:#1f1c30;--ink:#f3ecdc;--mut:#b2abc2;--pri:#5cc8c0;--pri2:#9be3dc;--onpri:#0b1f22;--line:#34304b;--ok:#8ddca0;--okbg:#17321f;--warn:#f3c978;--warnbg:#3a2a0c;--bad:#ff9d94;--badbg:#3a1717;--info:#9be3dc;--infobg:#143335}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 system-ui,-apple-system,"Segoe UI","Noto Sans","Noto Sans Bengali","Nirmala UI",sans-serif}
a{color:var(--pri)}
.skip{position:absolute;inset-inline-start:-999px;top:0;background:#000;color:#fff;padding:.5rem 1rem;z-index:20}
.skip:focus{inset-inline-start:0}
.wrap{max-width:980px;margin:0 auto;padding:1.25rem}
.top{background:var(--night);border-bottom:3px solid var(--acc);position:sticky;top:0;z-index:10}
.bar{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding-top:.55rem;padding-bottom:.55rem}
.brand{font:700 1.25rem Georgia,"Times New Roman",serif;letter-spacing:.02em;text-decoration:none;color:var(--acc)}
.nav{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.nav a:not(.btn){text-decoration:none;color:#f3ecdc;padding:.4rem .6rem;border-radius:8px}
.nav a:not(.btn):hover{background:#ffffff1a}
.btn{display:inline-block;border:2px solid var(--pri);background:var(--pri);color:var(--onpri);padding:.5rem 1.05rem;border-radius:999px;font:inherit;font-weight:700;cursor:pointer;text-decoration:none}
.btn:hover{filter:brightness(1.12)}
.btn.ghost{background:transparent;color:var(--pri)}
.btn.ghost:hover{background:var(--infobg)}
.btn.danger{background:var(--bad);border-color:var(--bad);color:var(--paper)}
.btn[disabled]{opacity:.6;cursor:not-allowed}
.top .btn.ghost{color:#f3ecdc;border-color:#f3ecdc66}
.top .btn.ghost:hover{background:#ffffff1a}
.top .btn:not(.ghost){background:var(--acc);border-color:var(--acc);color:#1d1b2f}
select.lang{width:auto;margin:0;padding:.4rem .6rem;border-radius:999px;border:2px solid #f3ecdc66;background:var(--night);color:#f3ecdc;font:inherit;max-width:11rem}
:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
h1,h2,h3{font-family:Georgia,"Times New Roman",serif}
h1{font-size:2.1rem;line-height:1.2;margin:.2rem 0 .6rem}
h2{font-size:1.4rem;margin:1.2rem 0 .5rem}
h3{font-size:1.1rem;margin:.2rem 0}
.mut{color:var(--mut)}
.hero{text-align:center;padding:2.4rem 1rem 1.6rem;margin-bottom:1rem;border-radius:var(--r);background:radial-gradient(circle at 20% 0,#e8a33d33,transparent 55%),radial-gradient(circle at 90% 100%,#0d5c6333,transparent 55%)}
.hero h1{font-size:2.5rem}
.hero p{max-width:640px;margin:.5rem auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}
.card{background:var(--paper);border:1px solid var(--line);border-inline-start:6px solid var(--acc);border-radius:var(--r);padding:1.1rem 1.2rem;box-shadow:0 2px 10px rgba(29,27,47,.07)}
a.card{display:block;color:inherit;text-decoration:none}
.card.pick{text-align:start;font:inherit;color:inherit;cursor:pointer;width:100%}
.card.pick:hover,a.card:hover{border-inline-start-color:var(--pri);transform:translateY(-2px)}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
.stack>*+*{margin-top:.9rem}
label.f{display:block;font-weight:700}
input[type=text],input[type=email],input[type=password],input[type=number],select{display:block;width:100%;margin-top:.25rem;padding:.6rem .8rem;border:2px solid var(--line);border-radius:12px;font:inherit;background:var(--paper);color:var(--ink)}
fieldset.fs{border:1px solid var(--line);border-radius:14px;padding:.8rem 1rem;margin:0}
legend{font-weight:700;padding:0 .4rem}
.opts{display:flex;flex-wrap:wrap;gap:.5rem}
.opt{display:flex;align-items:center;gap:.5rem;border:2px solid var(--line);background:var(--paper);border-radius:999px;padding:.4rem .9rem;cursor:pointer}
.opt:has(input:checked){border-color:var(--pri);background:var(--infobg)}
.alert{padding:.75rem 1rem;border-radius:12px;margin:.8rem 0;border-inline-start:5px solid currentColor}
.alert.err,.alert.unrealistic{background:var(--badbg);color:var(--bad)}
.alert.ok,.alert.realistic{background:var(--okbg);color:var(--ok)}
.alert.tight{background:var(--warnbg);color:var(--warn)}
.alert.info{background:var(--infobg);color:var(--info)}
progress{width:100%;height:.8rem;accent-color:var(--pri)}
.fit{display:flex;align-items:center;gap:.7rem}
.fit strong{min-width:3.4rem;font:700 1.3rem Georgia,serif;color:var(--pri)}
ul.clean{padding-inline-start:1.1rem;margin:.4rem 0}
.task{display:flex;gap:.7rem;align-items:flex-start;padding:.7rem 0;border-top:1px dashed var(--line)}
.task input{width:1.3rem;height:1.3rem;margin-top:.2rem;flex:none;accent-color:var(--pri)}
.task.done .tt{text-decoration:line-through;color:var(--mut)}
.badge{display:inline-block;background:var(--acc);color:#1d1b2f;border-radius:999px;padding:.05rem .75rem;font-size:.85rem;font-weight:700}
details{margin-top:.6rem}
summary{cursor:pointer;font-weight:700}
footer{color:var(--mut);font-size:.9rem;text-align:center;padding:2rem 1rem}
@media(max-width:560px){h1,.hero h1{font-size:1.65rem}.wrap{padding:1rem}}
@media(prefers-reduced-motion:no-preference){.card{transition:transform .15s,border-color .15s}}
""";

    // ===================================================================== FRONTEND: JavaScript
    static final String JS = """
'use strict';
// Every user-visible string is "English||Bangla". Bangla is built in; other languages are looked up
// in a pack (data/lang/<code>.tsv) keyed by the English text, and fall back to English.
const U={
 brand:'Destination AI||ডেস্টিনেশন এআই',
 tagline:'Find your direction. Plan your path. Make progress.||নিজের দিক খুঁজুন। পথ সাজান। এগিয়ে চলুন।',
 intro:'Not sure what to pursue, or know your goal but not how to reach it? Get explained options and a realistic plan built around your time and starting point.||কী করবেন বুঝতে পারছেন না, অথবা লক্ষ্য জানেন কিন্তু কীভাবে পৌঁছাবেন জানেন না? আপনার সময় ও শুরুর অবস্থা অনুযায়ী ব্যাখ্যাসহ বিকল্প ও বাস্তবসম্মত পরিকল্পনা পান।',
 check:'Check My Destination||আমার গন্তব্য যাচাই করুন',
 checkD:'Not sure what to choose? Answer a few questions and compare realistic options with their trade-offs.||কী বাছবেন বুঝতে পারছেন না? কয়েকটি প্রশ্নের উত্তর দিয়ে বাস্তবসম্মত বিকল্প ও তাদের সুবিধা-অসুবিধা তুলনা করুন।',
 prepare:'Prepare for the Destination||গন্তব্যের জন্য প্রস্তুত হই',
 prepareD:'Already know your goal? Get a step-by-step roadmap that fits your deadline and level.||লক্ষ্য জানেন? আপনার সময়সীমা ও স্তর অনুযায়ী ধাপে ধাপে রোডম্যাপ পান।',
 login:'Log in||লগইন', signup:'Sign up||সাইন আপ', logout:'Log out||লগআউট',
 myPlans:'My plans||আমার পরিকল্পনা', profile:'Profile||প্রোফাইল',
 name:'Full name||পূর্ণ নাম', email:'Email||ইমেইল', password:'Password||পাসওয়ার্ড',
 pwHint:'At least 8 characters.||কমপক্ষে ৮ অক্ষর।',
 haveAcc:'Already have an account? Log in||অ্যাকাউন্ট আছে? লগইন করুন',
 noAcc:'New here? Create an account||নতুন? অ্যাকাউন্ট খুলুন',
 pickDomain:'What area is this about?||এটি কোন ক্ষেত্র নিয়ে?',
 pickTask:'What exactly do you need help with?||ঠিক কী নিয়ে সাহায্য দরকার?',
 back:'Back||পেছনে', see:'See my options||আমার বিকল্প দেখুন',
 fit:'Estimated fit||আনুমানিক মিল', why:'Why this fits||কেন মিলছে', tradeoff:'Trade-off||সুবিধা-অসুবিধা',
 unknown:'What we do not know||যা আমরা জানি না', assume:'Assumptions||ধরে নেওয়া বিষয়',
 conf:'Confidence||আস্থার মাত্রা',
 choose:'Choose this and plan it||এটি বেছে পরিকল্পনা করুন', edit:'Change my answers||উত্তর বদলান',
 goalTitle:'Your destination (goal)||আপনার গন্তব্য (লক্ষ্য)',
 level:'Your current level||আপনার বর্তমান স্তর',
 weeks:'Weeks available||কত সপ্তাহ সময় আছে', hrs:'Hours per week||সপ্তাহে কত ঘণ্টা',
 wk:'weeks||সপ্তাহ', hw:'h/week||ঘণ্টা/সপ্তাহ',
 create:'Create my roadmap||আমার রোডম্যাপ বানান',
 emptyPlans:'You have no plans yet. Start with one of the journeys below.||এখনো কোনো পরিকল্পনা নেই। নিচের যেকোনো একটি দিয়ে শুরু করুন।',
 progress:'Progress||অগ্রগতি', done:'done||সম্পন্ন',
 delPlan:'Delete this plan||এই পরিকল্পনা মুছুন', confirmDelPlan:'Delete this plan permanently?||এই পরিকল্পনা স্থায়ীভাবে মুছবেন?',
 export:'Download my data||আমার তথ্য ডাউনলোড',
 delAcc:'Delete my account||আমার অ্যাকাউন্ট মুছুন',
 delWarn:'This permanently deletes your account and all plans. Enter your password to confirm.||এটি আপনার অ্যাকাউন্ট ও সব পরিকল্পনা স্থায়ীভাবে মুছে দেবে। নিশ্চিত করতে পাসওয়ার্ড দিন।',
 success:'What success means||সফলতা মানে কী', verify:'How to verify||যাচাই করবেন যেভাবে',
 how:'How||কীভাবে', hoursL:'about||প্রায়', hoursU:'hours||ঘণ্টা',
 feas:'Is the timeline realistic?||সময়সীমা কি বাস্তবসম্মত?',
 account:'Account||অ্যাকাউন্ট', saveNote:'Your plans are stored on this server under your account. You can download or delete them anytime.||আপনার পরিকল্পনা এই সার্ভারে আপনার অ্যাকাউন্টে সংরক্ষিত থাকে। যেকোনো সময় ডাউনলোড বা মুছতে পারবেন।',
 foot:'Destination AI gives guidance, not guarantees. Verify official requirements before making big decisions.||ডেস্টিনেশন এআই দিকনির্দেশনা দেয়, নিশ্চয়তা নয়। বড় সিদ্ধান্তের আগে অফিসিয়াল শর্ত যাচাই করুন।',
 loading:'Loading...||লোড হচ্ছে...', pleasePick:'Please choose one.||অনুগ্রহ করে একটি বাছাই করুন।',
 refine:'Refine results||ফলাফল আরও নির্দিষ্ট করুন', newCheck:'Start over||নতুন করে শুরু',
 noPack:'This language pack is not installed yet, so the app is shown in English.||এই ভাষার প্যাক এখনো ইনস্টল করা হয়নি, তাই অ্যাপ ইংরেজিতে দেখানো হচ্ছে।'
};
const SAVED=localStorage.getItem('lang'),BUILTIN=['en','bn'],PACKS={};
let lang=SAVED||'en',user=null,cfg=null,pending=null;
const D={step:1,domain:'',task:'',a:{interests:[],priority:'',hours:'',budget:'',style:''},res:null};
const P={domain:'',task:'',title:''};
const t=s=>{const p=String(s).split('||');if(lang==='bn'&&p[1])return p[1];const k=PACKS[lang];return (k&&k[p[0]])||p[0];};
const T=k=>t(U[k]);
const num=n=>{try{return new Intl.NumberFormat(lang==='fil'?'en':lang).format(n);}catch(e){return String(n);}};
async function loadPack(c){if(BUILTIN.includes(c)||PACKS[c])return;try{PACKS[c]=await api('/api/lang/'+c);}catch(e){PACKS[c]={};}}
async function setLang(c){await loadPack(c);lang=c;localStorage.setItem('lang',c);render();}

function h(tag,attrs,...kids){
 const e=document.createElement(tag);
 for(const [k,v] of Object.entries(attrs||{})){
  if(k==='class')e.className=v;
  else if(k.startsWith('on'))e.addEventListener(k.slice(2),v);
  else if(v===true)e.setAttribute(k,'');
  else if(v!==false&&v!=null)e.setAttribute(k,v);
 }
 for(const c of kids.flat(Infinity)){if(c==null||c===false)continue;e.append(c.nodeType?c:document.createTextNode(String(c)));}
 return e;
}
async function api(path,opts={}){
 const o={method:opts.method||'GET',headers:{'X-Requested-With':'fetch'},credentials:'same-origin'};
 if(opts.body){o.method='POST';o.headers['Content-Type']='application/x-www-form-urlencoded';o.body=new URLSearchParams(opts.body).toString();}
 const r=await fetch(path,o);let d={};
 try{d=await r.json();}catch(e){}
 if(!r.ok){const er=new Error(t(d.error||'Something went wrong.||কিছু ভুল হয়েছে।'));er.status=r.status;throw er;}
 return d;
}
const err=m=>h('div',{class:'alert err',role:'alert'},m);
const go=hash=>{location.hash=hash;};

// ---------- chrome
function header(){
 const nav=h('nav',{class:'nav','aria-label':'Main'});
 if(user){
  nav.append(h('a',{href:'#/goals'},T('myPlans')),h('a',{href:'#/profile'},T('profile')),h('button',{class:'btn ghost',onclick:logout},T('logout')));
 }else{
  nav.append(h('a',{href:'#/auth/login'},T('login')),h('a',{class:'btn',href:'#/auth/signup'},T('signup')));
 }
 nav.append(h('select',{class:'lang','aria-label':'Language',onchange:e=>setLang(e.target.value)},
  cfg.langs.map(l=>h('option',{value:l.code,selected:l.code===lang},l.name))));
 return h('header',{class:'top'},h('div',{class:'wrap bar'},h('a',{class:'brand',href:'#/'},'◎ '+T('brand')),nav));
}
async function logout(){try{await api('/api/logout',{body:{x:1}});}catch(e){}user=null;go('#/');render();}

// ---------- router
function render(){
 const L=cfg.langs.find(x=>x.code===lang);
 document.documentElement.lang=lang;
 document.documentElement.dir=L&&L.rtl?'rtl':'ltr';
 const m=h('main',{id:'app',class:'wrap',tabindex:'-1'});
 document.getElementById('root').replaceChildren(header(),m,h('footer',null,T('foot')));
 if(!BUILTIN.includes(lang)&&!Object.keys(PACKS[lang]||{}).length)
  m.append(h('div',{class:'alert info',role:'status'},T('noPack')));
 const parts=(location.hash||'#/').split('/'),a=parts[1]||'',b=parts[2]||'';
 const needAuth=['goals','goal','profile'];
 if(needAuth.includes(a)&&!user){pending=location.hash;go('#/auth/login');return;}
 const views={'':landing,discover:discover,prepare:prepareView,goals:goalsView,goal:goalView,auth:authView,profile:profileView};
 const v=views[a]||landing;
 Promise.resolve(v(m,b)).catch(e=>{
  if(e.status===401){user=null;pending=location.hash;go('#/auth/login');return;}
  m.replaceChildren(err(e.message));
 });
 window.scrollTo(0,0);
}

// ---------- views
function landing(m){
 m.append(h('section',{class:'hero'},h('h1',null,T('tagline')),h('p',{class:'mut'},T('intro'))),
  h('div',{class:'grid'},
   h('div',{class:'card stack'},h('h2',null,T('check')),h('p',{class:'mut'},T('checkD')),h('a',{class:'btn',href:'#/discover',onclick:resetDiscover},T('check'))),
   h('div',{class:'card stack'},h('h2',null,T('prepare')),h('p',{class:'mut'},T('prepareD')),h('a',{class:'btn',href:'#/prepare'},T('prepare')))));
}
function resetDiscover(){D.step=1;D.domain='';D.task='';D.res=null;D.a={interests:[],priority:'',hours:'',budget:'',style:''};}

function pickGrid(items,onPick){
 return h('div',{class:'grid'},items.map(i=>h('button',{type:'button',class:'card pick',onclick:()=>onPick(i)},h('h3',null,t(i.name)))));
}
function qField(q){
 const multi=q.type==='multi';
 return h('fieldset',{class:'fs'},h('legend',null,t(q.name)),
  h('div',{class:'opts'},q.options.map(o=>h('label',{class:'opt'},
   h('input',{type:multi?'checkbox':'radio',name:q.id,value:o.id,checked:multi?D.a[q.id].includes(o.id):D.a[q.id]===o.id}),
   h('span',null,t(o.name))))));
}
async function runRecommend(){
 const body={domain:D.domain,task:D.task,interests:D.a.interests.join(','),priority:D.a.priority,hours:D.a.hours,budget:D.a.budget,style:D.a.style};
 D.res=await api('/api/recommend',{body});D.step=4;render();
}
function discover(m){
 if(D.step===1){
  m.append(h('h1',null,T('check')),h('h2',null,T('pickDomain')),pickGrid(cfg.domains,i=>{D.domain=i.id;D.step=2;render();}));
 }else if(D.step===2){
  m.append(h('h1',null,T('check')),h('h2',null,T('pickTask')),
   pickGrid(cfg.tasks[D.domain],i=>{D.task=i.id;D.step=3;render();}),
   h('p',null,h('button',{class:'btn ghost',onclick:()=>{D.step=1;render();}},T('back'))));
 }else if(D.step===3){
  const form=h('form',{class:'stack',onsubmit:async e=>{
    e.preventDefault();const fd=new FormData(form);
    D.a.interests=fd.getAll('interests');
    for(const k of ['priority','hours','budget'])D.a[k]=fd.get(k)||'';
    try{await runRecommend();}catch(x){form.prepend(err(x.message));}
   }},
   cfg.questions.map(qField),
   h('div',{class:'row'},h('button',{type:'button',class:'btn ghost',onclick:()=>{D.step=2;render();}},T('back')),h('button',{class:'btn',type:'submit'},T('see'))));
  m.append(h('h1',null,T('check')),form);
 }else{
  const r=D.res;
  m.append(h('h1',null,T('check')),h('div',{class:'alert info'},t(r.note)+' '+T('conf')+': '+t(r.confidence)+'.'));
  if(r.assumptions.length)m.append(h('div',{class:'card'},h('strong',null,T('assume')),h('ul',{class:'clean'},r.assumptions.map(x=>h('li',null,t(x))))));
  if(r.followup){
   const q=r.followup;
   m.append(h('div',{class:'card stack'},h('fieldset',{class:'fs'},h('legend',null,t(q.name)),
    h('div',{class:'opts'},q.options.map(o=>h('label',{class:'opt'},
     h('input',{type:'radio',name:'style',value:o.id,onchange:async()=>{D.a.style=o.id;try{await runRecommend();}catch(x){m.prepend(err(x.message));}}}),h('span',null,t(o.name))))))));
  }
  m.append(h('div',{class:'stack'},r.results.map(x=>h('div',{class:'card'},
   h('h2',null,t(x.name)),
   h('div',{class:'fit'},h('strong',null,num(x.fit)+'%'),h('progress',{max:100,value:x.fit,'aria-label':T('fit')})),
   h('p',{class:'mut'},T('fit')),
   h('strong',null,T('why')),h('ul',{class:'clean'},x.reasons.map(y=>h('li',null,t(y)))),
   h('p',null,h('strong',null,T('tradeoff')+': '),t(x.tradeoff)),
   h('button',{class:'btn',onclick:()=>{P.domain=D.domain;P.task=D.task;P.title=t(x.name);go('#/prepare');}},T('choose'))))));
  m.append(h('div',{class:'card'},h('strong',null,T('unknown')),h('ul',{class:'clean'},r.unknowns.map(x=>h('li',null,t(x))))),
   h('div',{class:'row'},h('button',{class:'btn ghost',onclick:()=>{D.step=3;render();}},T('edit')),h('button',{class:'btn ghost',onclick:()=>{resetDiscover();render();}},T('newCheck'))));
 }
}
function opt(v,label,sel){return h('option',{value:v,selected:sel},label);}
function prepareView(m){
 if(!user){pending='#/prepare';go('#/auth/login');return;}
 if(!P.domain)P.domain=cfg.domains[0].id;
 const taskSel=h('select',{id:'task',name:'task'});
 const fillTasks=()=>taskSel.replaceChildren(...cfg.tasks[P.domain].map(x=>opt(x.id,t(x.name),x.id===P.task)));
 const domSel=h('select',{id:'domain',name:'domain',onchange:e=>{P.domain=e.target.value;P.task='';fillTasks();}},
  cfg.domains.map(x=>opt(x.id,t(x.name),x.id===P.domain)));
 fillTasks();
 const form=h('form',{class:'stack',onsubmit:async e=>{
   e.preventDefault();const fd=new FormData(form);
   try{const d=await api('/api/goals',{body:Object.fromEntries(fd)});P.title='';go('#/goal/'+d.id);}
   catch(x){form.prepend(err(x.message));}
  }},
  h('label',{class:'f',for:'domain'},T('pickDomain'),domSel),
  h('label',{class:'f',for:'task'},T('pickTask'),taskSel),
  h('label',{class:'f',for:'title'},T('goalTitle'),h('input',{type:'text',id:'title',name:'title',required:true,minlength:3,maxlength:120,value:P.title})),
  h('label',{class:'f',for:'level'},T('level'),h('select',{id:'level',name:'level'},cfg.levels.map(x=>opt(x.id,t(x.name),false)))),
  h('div',{class:'grid'},
   h('label',{class:'f',for:'weeks'},T('weeks'),h('input',{type:'number',id:'weeks',name:'weeks',min:1,max:104,value:8,required:true})),
   h('label',{class:'f',for:'hours'},T('hrs'),h('input',{type:'number',id:'hours',name:'hours',min:1,max:80,value:8,required:true}))),
  h('button',{class:'btn',type:'submit'},T('create')));
 m.append(h('h1',null,T('prepare')),h('div',{class:'card'},form));
}
async function goalsView(m){
 m.append(h('h1',null,T('myPlans')));
 const d=await api('/api/goals');
 if(!d.goals.length){
  m.append(h('p',{class:'mut'},T('emptyPlans')),h('div',{class:'row'},h('a',{class:'btn',href:'#/discover',onclick:resetDiscover},T('check')),h('a',{class:'btn ghost',href:'#/prepare'},T('prepare'))));
  return;
 }
 m.append(h('div',{class:'grid'},d.goals.map(g=>h('a',{class:'card',href:'#/goal/'+g.id},
  h('h3',null,g.title),h('p',{class:'mut'},num(g.weeks)+' '+T('wk')+' · '+num(g.hours)+' '+T('hw')),
  h('progress',{max:100,value:g.progress.percent,'aria-label':T('progress')}),
  h('small',{class:'mut'},num(g.progress.done)+'/'+num(g.progress.total)+' '+T('done'))))),
  h('p',null,h('a',{class:'btn',href:'#/prepare'},T('prepare'))));
}
async function goalView(m,id){
 const d=await api('/api/goals/'+encodeURIComponent(id));
 drawGoal(m,d,id);
}
function drawGoal(m,d,id){
 const r=d.roadmap;
 m.replaceChildren(
  h('p',null,h('a',{href:'#/goals'},'← '+T('myPlans'))),
  h('h1',null,r.title),
  h('div',{class:'alert '+r.feasibility.status,role:'status'},h('strong',null,T('feas')+' '),t(r.feasibility.message)),
  h('div',{class:'card'},h('strong',null,T('success')),h('p',null,t(r.success)),
   h('details',null,h('summary',null,T('assume')),h('ul',{class:'clean'},r.assumptions.map(x=>h('li',null,t(x)))))),
  h('div',{class:'card'},h('strong',null,T('progress')+': '+num(r.progress.percent)+'%'),
   h('progress',{max:100,value:r.progress.percent,'aria-label':T('progress')}),
   h('small',{class:'mut'},num(r.progress.done)+'/'+num(r.progress.total)+' '+T('done'))),
  r.phases.map(p=>h('section',{class:'card'},
   h('div',{class:'row'},h('h2',null,t(p.title)),h('span',{class:'badge'},t(p.weeks))),
   h('p',{class:'mut'},t(p.why)),h('p',null,h('strong',null,T('how')+': '),t(p.how)),
   p.tasks.map(k=>h('div',{class:'task'+(k.done?' done':'')},
    h('input',{type:'checkbox',id:'t'+k.id,checked:k.done,onchange:async()=>{
      try{const nd=await api('/api/goals/'+encodeURIComponent(id)+'/toggle',{body:{task:k.id}});drawGoal(m,nd,id);}
      catch(x){m.prepend(err(x.message));}
     }}),
    h('label',{for:'t'+k.id},h('span',{class:'tt'},t(k.title)),h('br'),
     h('small',{class:'mut'},T('verify')+': '+t(k.verify)+' · '+T('hoursL')+' '+num(k.hours)+' '+T('hoursU'))))))),
  h('p',null,h('button',{class:'btn danger',onclick:async()=>{
    if(!confirm(T('confirmDelPlan')))return;
    try{await api('/api/goals/'+encodeURIComponent(id)+'/delete',{body:{x:1}});go('#/goals');}catch(x){m.prepend(err(x.message));}
   }},T('delPlan'))));
}
function authView(m,mode){
 mode=mode==='signup'?'signup':'login';
 if(user){go('#/goals');return;}
 const form=h('form',{class:'stack',onsubmit:async e=>{
   e.preventDefault();const btn=form.querySelector('button[type=submit]');btn.disabled=true;
   try{const d=await api('/api/'+mode,{body:Object.fromEntries(new FormData(form))});user=d.user;const to=pending||'#/goals';pending=null;go(to);render();}
   catch(x){form.querySelector('.alert')?.remove();form.prepend(err(x.message));btn.disabled=false;}
  }},
  mode==='signup'?h('label',{class:'f',for:'name'},T('name'),h('input',{type:'text',id:'name',name:'name',required:true,minlength:2,maxlength:60,autocomplete:'name'})):null,
  h('label',{class:'f',for:'email'},T('email'),h('input',{type:'email',id:'email',name:'email',required:true,maxlength:254,autocomplete:'email'})),
  h('label',{class:'f',for:'password'},T('password'),h('input',{type:'password',id:'password',name:'password',required:true,minlength:mode==='signup'?8:1,maxlength:128,autocomplete:mode==='signup'?'new-password':'current-password'}),
   mode==='signup'?h('small',{class:'mut'},T('pwHint')):null),
  h('button',{class:'btn',type:'submit'},T(mode)),
  h('p',null,h('a',{href:'#/auth/'+(mode==='login'?'signup':'login')},T(mode==='login'?'noAcc':'haveAcc'))));
 m.append(h('div',{class:'card'},h('h1',null,T(mode)),form));
}
function profileView(m){
 const pw=h('input',{type:'password',id:'dpw',name:'password',required:true,autocomplete:'current-password'});
 const del=h('form',{class:'stack',onsubmit:async e=>{
   e.preventDefault();
   if(!confirm(T('delWarn')))return;
   try{await api('/api/account/delete',{body:{password:pw.value}});user=null;go('#/');render();}catch(x){del.prepend(err(x.message));}
  }},h('p',{class:'mut'},T('delWarn')),h('label',{class:'f',for:'dpw'},T('password'),pw),h('button',{class:'btn danger',type:'submit'},T('delAcc')));
 m.append(h('h1',null,T('profile')),
  h('div',{class:'card stack'},h('p',null,h('strong',null,user.name),h('br'),user.email),h('p',{class:'mut'},T('saveNote')),
   h('button',{class:'/ll,T('delAcc')),del));
}

// ---------- boot
(async function(){
 try{cfg=await api('/api/config');}catch(e){document.getElementById('root').textContent='Could not load. Please refresh.';return;}
 if(!SAVED){
  const g=(navigator.language||'en').toLowerCase();
  const f=cfg.langs.find(l=>l.code===g)||cfg.langs.find(l=>l.code===g.slice(0,2));
  if(f)lang=f.code;
 }
 if(!cfg.langs.some(l=>l.code===lang))lang='en';
 await loadPack(lang);
 try{user=(await api('/api/me')).user;}catch(e){user=null;}
 window.addEventListener('hashchange',render);
 render();
})();
""";
}
