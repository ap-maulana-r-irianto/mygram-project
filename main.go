package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"time"
)

var jwtKey = []byte("secret_key")

// Define User struct
type User struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Username        string    `gorm:"unique;not null" json:"username"`
	Email           string    `gorm:"unique;not null" json:"email"`
	Password        string    `gorm:"not null" json:"password"`
	Age             int       `gorm:"not null" json:"age"`
	ProfileImageURL string    `json:"profile_image_url"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Define Photo struct
type Photo struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `gorm:"not null" json:"title"`
	Caption   string    `json:"caption"`
	PhotoURL  string    `gorm:"not null" json:"photo_url"`
	UserID    uint      `gorm:"not null" json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Define Comment struct
type Comment struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"not null" json:"user_id"`
	PhotoID   uint      `gorm:"not null" json:"photo_id"`
	Message   string    `gorm:"not null" json:"message"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Define SocialMedia struct
type SocialMedias struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Name           string    `gorm:"not null" json:"name"`
	SocialMediaURL string    `gorm:"not null" json:"social_media_url"`
	UserID         uint      `gorm:"not null" json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Define Credentials struct for login
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var db *gorm.DB

func main() {
	// Connect to the database
	var err error
	dsn := "host=localhost user=postgres password= dbname=maulanarafaelirianto port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}

	// Migrate the schema
	db.AutoMigrate(&User{}, &Photo{}, &Comment{}, &SocialMedias{})

	router := gin.Default()

	router.POST("/users/register", register)
	router.POST("/users/login", login)

	userGroup := router.Group("/users")
	userGroup.Use(authMiddleware)
	{
		userGroup.PUT("/", updateUser)
		userGroup.DELETE("/", deleteUser)
	}

	router.POST("/photos", createPhoto)
	router.GET("/photos", getAllPhotos)
	router.GET("/photos/:photoId", getPhotoByID)
	router.PUT("/photos/:photoId", updatePhoto)
	router.DELETE("/photos/:photoId", deletePhoto)

	router.POST("/comments", createComment)
	router.GET("/comments", getAllComments)
	router.GET("/comments/:commentId", getCommentByID)
	router.PUT("/comments/:commentId", updateComment)
	router.DELETE("/comments/:commentId", deleteComment)

	router.POST("/socialmedias", createSocialMedia)
	router.GET("/socialmedias", getAllSocialMedia)
	router.GET("/socialmedias/:socialMediaId", getSocialMediaByID)
	router.PUT("/socialmedias/:socialMediaId", updateSocialMedia)
	router.DELETE("/socialmedias/:socialMediaId", deleteSocialMedia)

	router.Run(":8080")
}

// AuthMiddleware is a middleware to authenticate JWT tokens
func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if err != nil || !token.Valid {
		fmt.Println("Error while verifying token:", err)
		fmt.Println("Token validity:", token.Valid)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	c.Set("userId", claims["id"])
	c.Next()
}

// Register user handler
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Cek apakah email sudah digunakan
	var existingUser User
	if db.Where("email = ?", user.Email).First(&existingUser).RowsAffected > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	user.Password = string(hashedPassword)
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": user})
}

// Login user handler
func login(c *gin.Context) {
	var user User
	var inputUser User

	if err := c.ShouldBindJSON(&inputUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Cari user berdasarkan email
	db.Where("email = ?", inputUser.Email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Verifikasi password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(inputUser.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Buat token JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"id":    user.ID,
	})

	// Tandatangani token dengan secret key dan dapatkan string token
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Kirim token sebagai respons
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Update user handler
func updateUser(c *gin.Context) {
	var user User
	userId, _ := c.Get("userId")
	db.First(&user, userId)

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Save(&user)
	c.JSON(http.StatusOK, gin.H{"data": user})
}

// Delete user handler
func deleteUser(c *gin.Context) {
	var user User
	userId, _ := c.Get("userId")
	db.First(&user, userId)

	db.Delete(&user)
	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// Create photo handler
func createPhoto(c *gin.Context) {
	var photo Photo
	if err := c.ShouldBindJSON(&photo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mengambil userId dari konteks
	userIdRaw, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Mengonversi nilai userId menjadi uint
	userId, ok := userIdRaw.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid userId format in context"})
		return
	}

	// Mengatur userID dalam photo struct dengan nilai yang sesuai
	photo.UserID = userId

	// Membuat photo dalam database
	if err := db.Create(&photo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create photo"})
		return
	}

	// Menampilkan data photo yang berhasil dibuat
	c.JSON(http.StatusCreated, gin.H{"data": photo})
}

// Get all photos handler
func getAllPhotos(c *gin.Context) {
	var photos []Photo
	db.Find(&photos)
	c.JSON(http.StatusOK, gin.H{"data": photos})
}

// Get photo by ID handler
func getPhotoByID(c *gin.Context) {
	var photo Photo
	photoId := c.Param("photoId")

	db.First(&photo, photoId)
	c.JSON(http.StatusOK, gin.H{"data": photo})
}

// Update photo handler
func updatePhoto(c *gin.Context) {
	var photo Photo
	photoId := c.Param("photoId")

	db.First(&photo, photoId)

	if err := c.ShouldBindJSON(&photo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Save(&photo)
	c.JSON(http.StatusOK, gin.H{"data": photo})
}

// Delete photo handler
func deletePhoto(c *gin.Context) {
	var photo Photo
	photoId := c.Param("photoId")

	db.First(&photo, photoId)
	db.Delete(&photo)
	c.JSON(http.StatusOK, gin.H{"message": "Photo deleted successfully"})
}

// Create comment handler
func createComment(c *gin.Context) {
	var comment Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userId, _ := c.Get("userId")
	comment.UserID = userId.(uint)

	db.Create(&comment)
	c.JSON(http.StatusCreated, gin.H{"data": comment})
}

// Get all comments handler
func getAllComments(c *gin.Context) {
	var comments []Comment
	db.Find(&comments)
	c.JSON(http.StatusOK, gin.H{"data": comments})
}

// Get comment by ID handler
func getCommentByID(c *gin.Context) {
	var comment Comment
	commentId := c.Param("commentId")

	db.First(&comment, commentId)
	c.JSON(http.StatusOK, gin.H{"data": comment})
}

// Update comment handler
func updateComment(c *gin.Context) {
	var comment Comment
	commentId := c.Param("commentId")

	db.First(&comment, commentId)

	if err := c.ShouldBindJSON(&comment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Save(&comment)
	c.JSON(http.StatusOK, gin.H{"data": comment})
}

// Delete comment handler
func deleteComment(c *gin.Context) {
	var comment Comment
	commentId := c.Param("commentId")

	db.First(&comment, commentId)
	db.Delete(&comment)
	c.JSON(http.StatusOK, gin.H{"message": "Comment deleted successfully"})
}

// Create social media handler
func createSocialMedia(c *gin.Context) {
	var socialMedia SocialMedias
	if err := c.ShouldBindJSON(&socialMedia); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userId, _ := c.Get("userId")
	socialMedia.UserID = userId.(uint)

	db.Create(&socialMedia)
	c.JSON(http.StatusCreated, gin.H{"data": socialMedia})
}

// Get all social media handler
func getAllSocialMedia(c *gin.Context) {
	var socialMedias []SocialMedias
	userId, _ := c.Get("userId")
	db.Where("user_id = ?", userId).Find(&socialMedias)
	c.JSON(http.StatusOK, gin.H{"data": socialMedias})
}

// Get social media by ID handler
func getSocialMediaByID(c *gin.Context) {
	var socialMedia SocialMedias
	socialMediaId := c.Param("socialMediaId")
	userId, _ := c.Get("userId")
	db.Where("user_id = ? AND id = ?", userId, socialMediaId).First(&socialMedia)
	c.JSON(http.StatusOK, gin.H{"data": socialMedia})
}

// Update social media handler
func updateSocialMedia(c *gin.Context) {
	var socialMedia SocialMedias
	socialMediaId := c.Param("socialMediaId")
	userId, _ := c.Get("userId")
	db.Where("user_id = ? AND id = ?", userId, socialMediaId).First(&socialMedia)

	if err := c.ShouldBindJSON(&socialMedia); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Save(&socialMedia)
	c.JSON(http.StatusOK, gin.H{"data": socialMedia})
}

// Delete social media handler
func deleteSocialMedia(c *gin.Context) {
	var socialMedia SocialMedias
	socialMediaId := c.Param("socialMediaId")
	userId, _ := c.Get("userId")
	db.Where("user_id = ? AND id = ?", userId, socialMediaId).First(&socialMedia)
	db.Delete(&socialMedia)
	c.JSON(http.StatusOK, gin.H{"message": "Social media deleted successfully"})
}
