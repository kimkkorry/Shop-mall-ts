import express from 'express'
import pg from 'pg'
import cors from 'cors'
import bcrypt from 'bcrypt'
import session from 'express-session'

// express 객체 생성
const app = express();
const PORT = process.env.PORT || 8000;

// 운영 모드: 배포(Render) 인지 확인
const isProduction = process.env.NODE_ENV === "production"

// DB 연결
const db = process.env.DATABASE_URL
  ? new pg.Client({ connectionString: process.env.DATABASE_URL})
  : new pg.Client({
        host: "localhost",
        user: "jsuser",
        password: "pwjs",
        database: "tsdb"
    })

try{
    await db.connect();
    console.log("PostgreSQL 연결 성공!");
}catch(err){
    console.error("PostgreSQL 연결 실패!", err.message);
}

// Render는 앞단 프록시(https)를 거쳐 요청이 들어오므로, 프록시를 믿어야 
// secure 쿠키가 동작합니다.
if(isProduction){
    app.set("trust proxy", 1);
}

// 허용할 프론트엔드 주소 설정 (Render 클라이언트 주소를 여기에 명시하거나 환경변수로 받음)
const allowedOrigins = [
    "http://localhost:5173",
    "https://shop-mall-ts-client.onrender.com", // 프론트엔드 Render 주소 추가
    ...(process.env.CLIENT_URL
        ? process.env.CLIENT_URL.split(",").map(s => s.trim())
        : [])
];

// cors 설정
app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));

// 세션 설정
app.use(session({
    secret: process.env.SESSION_SECRET || "space-shop-secret",
    resave: false,  
    saveUninitialized: false,  
    cookie: {
        httpOnly: true,  
        maxAge: 1000 * 60 * 60,   // 1시간
        sameSite: isProduction ? "none" : "lax",
        secure: isProduction
    }  
}));

// 본문 요청 파싱
app.use(express.json());

// 로그인했는지 확인하는 함수 - 인증(Authentication)
const requireLogin = (req, res, next ) => {
    if(!req.session.user){
        return res.status(401).send("로그인이 필요합니다.")
    }
    next();
}

// 관리자인지 확인 - 권한(role)
const requireAdmin = (req, res, next ) => {
    if(req.session.user?.role !== "admin"){
        return res.status(403).send("관리자만 사용할 수 있습니다.")
    }
    next();
}

// 기본 라우터
app.get("/", (req, res) => {
    res.send("<h1>쇼핑몰 서버 API 개발</h1>")
})

// 상품 목록 조회
app.get("/api/products", async (req, res) => {
    const sql = "SELECT * FROM products";
    try{
        const result = await db.query(sql);
        res.json(result.rows);  
    }catch(err){
        console.error("상품 목록 조회 오류!!", err);
        res.status(500).send("상품 목록 조회 오류!!")
    }
});

// 상품 1건 조회
app.get("/api/products/:id", async (req, res) => {
    const pid = req.params.id;  
    const sql = "SELECT * FROM products WHERE id = $1";
    try{
        const result = await db.query(sql, [pid]); 
        res.json(result.rows[0]);  
    }catch(err){
        console.error("상품 조회 오류!!", err);
        res.status(500).send("상품 조회 오류!!")
    }
});

// 상품 등록
app.post("/api/products", requireAdmin, async (req, res) => {
    const { pName, category, price, description, image} = req.body;
    const sql = "INSERT INTO products(p_name, category, price, description, "
       + " image) VALUES ($1, $2, $3, $4, $5)";
    try{
        await db.query(sql, [pName, category, price, description, image ?? null]);
        res.send("상품 등록 완료!");
    }catch(err){
         console.error("상품 등록 오류!!", err);
        res.status(500).send("상품 등록 오류!!")
    }
})

// 상품 삭제
app.delete("/api/products/:id", requireAdmin, async (req, res) => {
    const pid = req.params.id;  
    const sql = "DELETE FROM products WHERE id = $1";
    try{
        await db.query(sql, [pid]); 
        res.send("상품 삭제 완료!")  
    }catch(err){
        console.error("상품 삭제 오류!!", err);
        res.status(500).send("상품 삭제 오류!!")
    }
});

// 상품 수정
app.put("/api/products/:id", requireAdmin, async (req, res) => {
    const pid = req.params.id;
    const { pName, category, price, description, image} = req.body;
    const sql = "UPDATE products SET p_name=$1, category=$2, price=$3, "
         + " description=$4, image=$5 WHERE id = $6";
    try{
        await db.query(sql, [pName, category, price, description, image ?? null, pid]);
        res.send("상품 수정 완료!");
    }catch(err){
        console.error("상품 수정 오류!!", err);
        res.status(500).send("상품 수정 오류!!")
    }
})

// 회원 목록
app.get("/api/users", async (req, res) => {
    const sql = "SELECT * FROM users";
    try{
        const result = await db.query(sql);
        res.json(result.rows);  
    }catch(err){
        console.error("회원 목록 조회 오류!!", err);
        res.status(500).send("회원 목록 조회 오류!!")
    } 
});

// 회원 가입
app.post("/api/users", async (req, res) => {
    const { username, password, name, email } = req.body;
    const sql = "INSERT INTO users(username, password, name, email) "
            + "VALUES ($1, $2, $3, $4)";
    try{
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query(sql, [username, hashedPassword, name, email]);
        res.send("회원 가입 완료!");
    }catch(err){
        console.error("회원가입 중 오류!!", err);
        res.status(500).send("회원가입 중 오류!!")
    } 
});

// 로그인 - 비밀번호 암호화
app.post("/api/users/login", async (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username=$1";
    try{
        const result = await db.query(sql, [username]);
        const user = result.rows[0];

        if(!user || !(await bcrypt.compare(password, user.password))){
            return res.status(401).send("아이디 또는 비밀번호가 일치하지 않습니다.");
        }
        const { password: _, ...userInfo } = user;
        req.session.user = userInfo; 
        res.json({
            message: "로그인 성공",
            user: userInfo
        });  
    }catch(err){
        console.error("회원 로그인 중 오류!!", err);
        res.status(500).send("회원 로그인 중 오류!!")
    } 
});

// 로그인 확인
app.get("/api/users/me", requireLogin, (req, res) => {
    res.json(req.session.user);
})

// 로그아웃 (connect.sid 쿠키 삭제로 수정)
app.post("/api/users/logout", (req, res) => {
    req.session.destroy(() => { 
        res.clearCookie("connect.sid");
        res.send("로그아웃 완료!");
    });
});

// 회원 정보 변경
app.put("/api/users/:id", requireLogin, async (req, res) => {
    if(req.session.user.id !== Number(req.params.id)){
        return res.status(403).send("본인 정보만 수정할 수 있습니다.")
    }
    
    const uid = req.params.id;
    const { name, email } = req.body;

    const sql = "UPDATE users SET name=$1, email=$2 WHERE id=$3 "
        + "RETURNING id, username, name, email, role, created_at";
    try{
       const result = await db.query(sql, [name, email, uid]);
        if(result.rows.length === 0){
            return res.status(404).send("회원을 찾을 수 없습니다.");
        }
        req.session.user = result.rows[0];  
        res.json(result.rows[0]);  
    }catch(err){
        if(err.code === "23505"){
            return res.status(409).send("이미 사용중인 이메일입니다.");
        }
        console.error("회원 정보 수정 중 오류!!", err);
        res.status(500).send("회원 정보 수정 중 오류!!")
    }
})

// 서버 실행
app.listen(PORT, () => {
    console.log(`서버 실행중... http://localhost:${PORT}`);
})