package controllers

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go_jwt/database"
	helper "go_jwt/helpers"
	"go_jwt/models"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"time"
)

var UserCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	isPasswordValid := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("Email ot Password is incorrect")
		isPasswordValid = false
	}
	return isPasswordValid, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		// count = no of records with same email
		count, err := UserCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
		}
		defer cancel()

		password := HashPassword(*user.Password)
		user.Password = &password

		// count = no of records with same phone number
		count, err = UserCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone number"})
		}
		defer cancel()

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
		}

		user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.UserId = user.ID.Hex()

		// generate token and refresh token
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.FirstName, *user.LastName, *user.UserType, *&user.UserId)
		user.Token = &token //what happens if just token
		user.RefreshToken = &refreshToken

		// insert this created user into the DB
		resultInsertionNumber, insertErr := UserCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		// serialize JSON details from response into user
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// get the user using the email and unmarshall it into foundUser
		err := UserCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Email or Password is incorrect"})
			return
		}

		//verify password and email
		isPasswordValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()

		if isPasswordValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		}

		// generate token and refresh token
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, *foundUser.UserType, foundUser.UserId)
		helper.UpdateAllTokens(token, refreshToken, foundUser.UserId)
		err = UserCollection.FindOne(ctx, bson.M{"user_id": foundUser.UserId}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}

}

//Only admin can access this
func GetUserbyId() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		err := helper.MatchUserTypeToUuid(c, userId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		err2 := UserCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}

//Only admin can access this
func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Only ADMIN users can access this fn
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		// get "recordPerPage" from query and parse it to integer
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10 //default
		}

		pagenumber, err1 := strconv.Atoi(c.Query("pageNumber"))
		if err1 != nil || pagenumber < 1 {
			pagenumber = 1 //default
		}

		// MongoDB aggregations ??
		cursor, err := UserCollection.Find(ctx, bson.M{})
		if err != nil {
			log.Fatal(err)
		}
		defer cursor.Close(ctx)

		defer cancel()

		var allUsers []bson.M
		for cursor.Next(ctx) {
			if err = cursor.Decode(&allUsers); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while listing user items"})
			}
			fmt.Println(allUsers)
		}
		c.JSON(http.StatusOK, allUsers)
	}
}
