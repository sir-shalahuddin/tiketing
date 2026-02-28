package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	_ "ticketing/docs"

	jwt "github.com/golang-jwt/jwt/v5"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// --- DTO DEFINITIONS ---

type LoginRequest struct {
	Username string `json:"username" example:"admin"`
	Password string `json:"password" example:"admin123"`
}

type UserDTO struct {
	ID       string `json:"id" example:"USR-123"`
	Username string `json:"username" example:"siraj"`
	Password string `json:"password,omitempty" example:"rahasia"`
	Role     string `json:"role" example:"Admin"`
	Name     string `json:"name" example:"Siraj Shalahuddin"`
	Phone    string `json:"phone" example:"62812345678"`
}

type TicketDTO struct {
	ID            string    `json:"id" example:"TCK-167890"`
	Title         string    `json:"title" example:"Internet Down"`
	Description   string    `json:"description" example:"Cannot connect to wifi"`
	Type          string    `json:"type" example:"Troubleshoot"`
	Status        string    `json:"status" example:"Open"`
	UserID        string    `json:"user_id" example:"USR-1"`
	UserName      string    `json:"user_name"`
	UserPhone     string    `json:"user_phone"`
	TechID        string    `json:"tech_id" example:"USR-2"`
	TechName      string    `json:"tech_name"`
	TechPhone     string    `json:"tech_phone"`
	AttachmentURL string    `json:"attachment_url" example:"/uploads/file.png"`
	CreatedAt     time.Time `json:"created_at"`
}

type UpdateTicketDTO struct {
	ID          string `json:"id" example:"TCK-167890"`
	Status      string `json:"status" example:"In Progress"`
	TechID      string `json:"tech_id" example:"USR-2"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

var db *sql.DB

// @title IT Helpdesk API
// @version 1.0
// @host localhost:8080
// @BasePath /
func main() {
	// 1. Inisialisasi DB
	var err error
	db, err = sql.Open("sqlite", "./helpdesk.db")
	if err != nil {
		log.Fatal(err)
	}

	db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
	initDB()

	// 2. Setup Router
	mux := http.NewServeMux()
	setupRoutes(mux) // Masukkan semua mux.HandleFunc Anda ke fungsi ini agar rapi

	// 3. Konfigurasi Server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// 4. Jalankan Server dalam Goroutine
	// Agar tidak memblock main thread yang akan menunggu signal
	go func() {
		fmt.Println("🚀 Server: http://localhost:8080 | Swagger: /swagger/index.html")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen error: %s\n", err)
		}
	}()

	// 5. Menunggu Signal dari Sistem Operasi
	// Membuat channel untuk menerima signal (SIGINT = Ctrl+C, SIGTERM = Kill signal)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit // Program akan "berhenti" di sini sampai ada signal masuk
	fmt.Println("\n⚠️ Mematikan server secara halus...")

	// 6. Membuat Context dengan Timeout (misal 10 detik)
	// Memberikan waktu bagi request yang sedang berjalan untuk selesai
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 7. Proses Shutdown
	// Stop menerima request baru dan tunggu request aktif selesai
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %s", err)
	}

	// 8. Tutup Resources Lain (Database)
	// Sangat penting untuk SQLite agar semua WAL jurnal ditulis ke file utama
	if err := db.Close(); err != nil {
		log.Fatalf("Gagal menutup database: %s", err)
	}

	fmt.Println("✅ Server berhasil berhenti tanpa masalah.")
}

func setupRoutes(mux *http.ServeMux) {
	// Static & Swagger
	mux.Handle("/swagger/", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))
	mux.Handle("/", http.FileServer(http.Dir("./frontend")))

	// API Routes (Go 1.22+ Style: Method + Path)
	mux.HandleFunc("POST /api/login", loginHandler)

	mux.HandleFunc("GET /api/users", authMiddleware(getUsersHandler))
	mux.HandleFunc("POST /api/users", authMiddleware(createUserHandler))
	mux.HandleFunc("DELETE /api/users", authMiddleware(deleteUserHandler))

	mux.HandleFunc("GET /api/tickets", authMiddleware(getTicketsHandler))
	mux.HandleFunc("POST /api/tickets", authMiddleware(createTicketHandler))
	mux.HandleFunc("PUT /api/tickets", authMiddleware(updateTicketHandler))
	mux.HandleFunc("DELETE /api/tickets", authMiddleware(deleteTicketHandler))
}

func initDB() {
	db.Exec(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, name TEXT, phone TEXT);`)
	db.Exec(`CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, title TEXT, description TEXT, status TEXT, user_id TEXT, tech_id TEXT, attachment_url TEXT, created_at DATETIME);`)
	db.Exec(`ALTER TABLE tickets ADD COLUMN type TEXT DEFAULT '';`)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
	if count == 0 {
		h, _ := bcrypt.GenerateFromPassword([]byte("admin123"), 10)
		db.Exec("INSERT INTO users VALUES ('u1', 'admin', ?, 'Admin', 'Super Admin', '628123456789')", string(h))
	}

	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'tech'").Scan(&count)
	if count == 0 {
		h, _ := bcrypt.GenerateFromPassword([]byte("tech123"), 10)
		db.Exec("INSERT INTO users VALUES ('u2', 'tech', ?, 'Tech', 'Tech Support 1', '628123456790')", string(h))
	}

	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'tech2'").Scan(&count)
	if count == 0 {
		h, _ := bcrypt.GenerateFromPassword([]byte("tech123"), 10)
		db.Exec("INSERT INTO users VALUES ('u2b', 'tech2', ?, 'Tech', 'Tech Support 2', '628123456792')", string(h))
	}

	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'user'").Scan(&count)
	if count == 0 {
		h, _ := bcrypt.GenerateFromPassword([]byte("user123"), 10)
		db.Exec("INSERT INTO users VALUES ('u3', 'user', ?, 'User', 'Normal User', '628123456791')", string(h))
	}
}

// --- AUTH HANDLER ---

// @Summary Login User
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body LoginRequest true "Credentials"
// @Success 200 {object} UserDTO
// @Router /api/login [post]
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	json.NewDecoder(r.Body).Decode(&req)
	// log.Printf("🔍 Mencoba login: [%s] dengan password: [%s]\n", req.Username, req.Password)
	var u UserDTO
	var hash string
	err := db.QueryRow("SELECT id, username, password, role, name, phone FROM users WHERE username = ?", req.Username).Scan(&u.ID, &u.Username, &hash, &u.Role, &u.Name, &u.Phone)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		w.WriteHeader(401)
		return
	}
	u.Password = ""
	token, _ := generateToken(u.ID, u.Role)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user":  u,
	})

}

// --- USER HANDLERS ---

// @Summary Get All Users
// @Tags Users
// @Produce json
// @Success 200 {array} UserDTO
// @Router /api/users [get]
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id, username, role, name, phone FROM users")
	var users []UserDTO
	for rows.Next() {
		var u UserDTO
		rows.Scan(&u.ID, &u.Username, &u.Role, &u.Name, &u.Phone)
		users = append(users, u)
	}
	json.NewEncoder(w).Encode(users)
}

// @Summary Create New User
// @Tags Users
// @Accept json
// @Param body body UserDTO true "User Data"
// @Success 201
// @Router /api/users [post]
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(contextKeyClaims).(*Claims)
	if claims.Role != "User" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var u UserDTO
	json.NewDecoder(r.Body).Decode(&u)
	h, _ := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
	id := fmt.Sprintf("USR-%d", time.Now().Unix())
	db.Exec("INSERT INTO users VALUES (?,?,?,?,?,?)", id, u.Username, string(h), u.Role, u.Name, u.Phone)
	w.WriteHeader(201)
}

// @Summary Delete User
// @Tags Users
// @Param id query string true "User ID"
// @Success 200
// @Router /api/users [delete]
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(contextKeyClaims).(*Claims)
	if claims.Role != "User" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM users WHERE id = ?", id)
	w.WriteHeader(200)
}

// --- TICKET HANDLERS ---

// @Summary Get All Tickets
// @Tags Tickets
// @Produce json
// @Success 200 {array} TicketDTO
// @Router /api/tickets [get]
func getTicketsHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextKeyClaims).(*Claims)
	if !ok {
		w.WriteHeader(401)
		return
	}

	query := `
		SELECT t.id, t.title, t.description, t.status, t.type, 
		       t.user_id, COALESCE(u.name, ''), COALESCE(u.phone, ''),
		       COALESCE(t.tech_id, ''), COALESCE(tech.name, ''), COALESCE(tech.phone, ''),
		       t.attachment_url, t.created_at
		FROM tickets t
		LEFT JOIN users u ON t.user_id = u.id
		LEFT JOIN users tech ON t.tech_id = tech.id
	`
	var rows *sql.Rows
	var err error

	if claims.Role == "User" {
		query += " WHERE t.user_id = ? ORDER BY t.created_at DESC"
		rows, err = db.Query(query, claims.UserID)
	} else if claims.Role == "Tech" {
		query += " WHERE t.tech_id = ? ORDER BY t.created_at DESC"
		rows, err = db.Query(query, claims.UserID)
	} else {
		query += " ORDER BY t.created_at DESC"
		rows, err = db.Query(query)
	}

	if err != nil {
		w.WriteHeader(500)
		return
	}
	defer rows.Close()

	var list []TicketDTO
	for rows.Next() {
		var t TicketDTO
		rows.Scan(&t.ID, &t.Title, &t.Description, &t.Status, &t.Type, &t.UserID, &t.UserName, &t.UserPhone, &t.TechID, &t.TechName, &t.TechPhone, &t.AttachmentURL, &t.CreatedAt)
		list = append(list, t)
	}
	// Return empty array instead of null
	if list == nil {
		list = []TicketDTO{}
	}
	json.NewEncoder(w).Encode(list)
}

// @Summary Create Ticket with Attachment
// @Tags Tickets
// @Accept multipart/form-data
// @Param title formData string true "Title"
// @Param description formData string true "Description"
// @Param type formData string true "Type"
// @Param attachment formData file false "Attachment"
// @Success 201
// @Router /api/tickets [post]
func createTicketHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(contextKeyClaims).(*Claims)
	if claims.Role != "User" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	r.ParseMultipartForm(10 << 20)
	file, head, err := r.FormFile("attachment")
	path := ""
	if err == nil {
		path = "/uploads/" + fmt.Sprintf("%d_%s", time.Now().Unix(), head.Filename)
		dst, _ := os.Create("." + path)
		defer dst.Close()
		io.Copy(dst, file)
	}
	id := fmt.Sprintf("TCK-%d", time.Now().Unix())
	db.Exec("INSERT INTO tickets (id, title, description, status, type, user_id, tech_id, attachment_url, created_at) VALUES (?,?,?, 'Open', ?, ?, '', ?, ?)", 
		id, r.FormValue("title"), r.FormValue("description"), r.FormValue("type"), claims.UserID, path, time.Now())
	w.WriteHeader(201)
}

// @Summary Update Ticket Status/Assign
// @Tags Tickets
// @Accept json
// @Param body body UpdateTicketDTO true "Update Data"
// @Success 200
// @Router /api/tickets [put]
func updateTicketHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(contextKeyClaims).(*Claims)
	var req UpdateTicketDTO
	json.NewDecoder(r.Body).Decode(&req)

	if claims.Role == "Admin" {
		if req.TechID != "" {
			db.Exec(`UPDATE tickets SET tech_id=?, status='Assigned' WHERE id=?`, req.TechID, req.ID)
		} else {
			db.Exec(`UPDATE tickets SET tech_id='', status='Open' WHERE id=?`, req.ID)
		}
	} else if claims.Role == "Tech" {
		// Tech can only change status, but NOT back to Open
		if req.Status != "" && req.Status != "Open" {
			db.Exec(`UPDATE tickets SET status=? WHERE id=? AND tech_id=?`, req.Status, req.ID, claims.UserID)
		} else if req.Status == "Open" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(200)
}

// @Summary Delete Ticket
// @Tags Tickets
// @Param id query string true "Ticket ID"
// @Success 200
// @Router /api/tickets [delete]
func deleteTicketHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(contextKeyClaims).(*Claims)
	if claims.Role != "User" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM tickets WHERE id = ?", id)
	w.WriteHeader(200)
}

var jwtKey = []byte("rahasia_perusahaan_2026") // Di produksi, gunakan ENV

type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// Fungsi bantu generate Token
func generateToken(userID, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:           userID,
		Role:             role,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expirationTime)},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

type contextKey string
const contextKeyClaims = contextKey("claims")

// MIDDLEWARE SECURITY
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Simpan info user ke context jika perlu
		ctx := context.WithValue(r.Context(), contextKeyClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
