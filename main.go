package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	// Используем новый секретный ключ и настраиваем параметры сессии
	store = sessions.NewCookieStore([]byte("a-completely-new-secret-key-2023-11"))
	tmpl  = template.Must(template.ParseGlob("templates/*.html"))
)

func init() {
	// Настраиваем параметры сессий для разработки
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 дней
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Используем Lax режим для разработки
		Secure:   false,                // Отключаем HTTPS для локальной разработки
	}
}

// Обертка для работы с сессиями
func getSession(r *http.Request) (*sessions.Session, error) {
	// Пытаемся получить сессию
	session, err := store.Get(r, "session")
	if err != nil {
		// Если возникла ошибка, создаем новую сессию
		log.Printf("Ошибка получения сессии: %v - создаем новую", err)
		session = sessions.NewSession(store, "session")
		session.IsNew = true
		return session, nil
	}
	return session, nil
}

func initializeApp() error {
	// Создаем директории, если они не существуют
	dirs := []string{"images", "static"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Открываем соединение с базой данных
	db, err := sql.Open("sqlite3", "./recipes.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// Создаем таблицы
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS recipes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			title TEXT NOT NULL,
			ingredients TEXT NOT NULL,
			instructions TEXT NOT NULL,
			photo TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS favorites (
			user_id INTEGER,
			recipe_id INTEGER,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (recipe_id) REFERENCES recipes(id),
			PRIMARY KEY (user_id, recipe_id)
		)`,
		`CREATE TABLE IF NOT EXISTS comments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			recipe_id INTEGER,
			content TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (recipe_id) REFERENCES recipes(id)
		)`,
		`CREATE TABLE IF NOT EXISTS reactions (
			user_id INTEGER,
			recipe_id INTEGER,
			type TEXT CHECK(type IN ('like', 'dislike')),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (recipe_id) REFERENCES recipes(id),
			PRIMARY KEY (user_id, recipe_id)
		)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %v", err)
		}
	}

	return nil
}

func main() {
	// Инициализация приложения
	if err := initializeApp(); err != nil {
		log.Fatal("Failed to initialize application:", err)
	}

	db, err := sql.Open("sqlite3", "./recipes.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Проверяем соединение с базой данных
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Добавляем обработчик всех ошибок
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Устанавливаем заголовки для лучшей совместимости
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		// Если запрос к корневому маршруту, вызываем indexHandler
		if r.URL.Path == "/" {
			indexHandler(w, r, db)
			return
		}

		// Иначе считаем, что это неизвестный маршрут
		http.NotFound(w, r)
	})

	http.HandleFunc("/about", aboutHandler)
	http.HandleFunc("/recipes", func(w http.ResponseWriter, r *http.Request) {
		recipesHandler(w, r, db)
	})
	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		profileHandler(w, r, db)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, db)
	})
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerHandler(w, r, db)
	})
	http.HandleFunc("/add_recipe", func(w http.ResponseWriter, r *http.Request) {
		addRecipeHandler(w, r, db)
	})
	http.HandleFunc("/delete_recipe", func(w http.ResponseWriter, r *http.Request) {
		deleteRecipeHandler(w, r, db)
	})
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/add_favorite", func(w http.ResponseWriter, r *http.Request) {
		addFavoriteHandler(w, r, db)
	})
	http.HandleFunc("/remove_favorite", func(w http.ResponseWriter, r *http.Request) {
		removeFavoriteHandler(w, r, db)
	})
	http.HandleFunc("/favorites", func(w http.ResponseWriter, r *http.Request) {
		favoritesHandler(w, r, db)
	})
	http.HandleFunc("/add_comment", func(w http.ResponseWriter, r *http.Request) {
		addCommentHandler(w, r, db)
	})
	http.HandleFunc("/add_reaction", func(w http.ResponseWriter, r *http.Request) {
		addReactionHandler(w, r, db)
	})

	// Добавляем страницу отладки
	http.HandleFunc("/debug_session", func(w http.ResponseWriter, r *http.Request) {
		// Проверка, что мы в режиме разработки
		debugSessionHandler(w, r)
	})

	// Обработчик для статических файлов
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Username": session.Values["username"],
	})
	if err != nil {
		log.Printf("Ошибка отображения шаблона index: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, "about.html", map[string]interface{}{
		"Username": session.Values["username"],
	})
	if err != nil {
		log.Printf("Ошибка отображения шаблона about: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func recipesHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	username := session.Values["username"]
	log.Printf("Пользователь %v просматривает рецепты", username)

	var currentUserID int
	if username != nil {
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&currentUserID)
		if err != nil {
			log.Printf("Ошибка получения ID пользователя: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}
	}

	rows, err := db.Query(`
		SELECT r.id, r.user_id, r.title, r.ingredients, r.instructions, r.photo, r.created_at,
			   u.username as author,
			   (SELECT COUNT(*) FROM reactions WHERE recipe_id = r.id AND type = 'like') as likes,
			   (SELECT COUNT(*) FROM reactions WHERE recipe_id = r.id AND type = 'dislike') as dislikes,
			   (SELECT type FROM reactions WHERE recipe_id = r.id AND user_id = ? AND type = 'like') as user_liked,
			   (SELECT type FROM reactions WHERE recipe_id = r.id AND user_id = ? AND type = 'dislike') as user_disliked
		FROM recipes r
		JOIN users u ON r.user_id = u.id
		ORDER BY r.created_at DESC`, currentUserID, currentUserID)
	if err != nil {
		log.Printf("Ошибка получения рецептов: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var recipes []map[string]interface{}
	for rows.Next() {
		var id, userID int
		var title, ingredients, instructions, photo, author string
		var createdAt string
		var likes, dislikes int
		var userLiked, userDisliked sql.NullString

		if err := rows.Scan(&id, &userID, &title, &ingredients, &instructions, &photo, &createdAt, &author, &likes, &dislikes, &userLiked, &userDisliked); err != nil {
			log.Printf("Ошибка сканирования данных рецепта: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		log.Printf("Загружен рецепт ID: %d, путь к фото: %s", id, photo)

		// Получаем комментарии для рецепта
		commentsRows, err := db.Query(`
			SELECT c.content, c.created_at, u.username
			FROM comments c
			JOIN users u ON c.user_id = u.id
			WHERE c.recipe_id = ?
			ORDER BY c.created_at DESC`, id)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		defer commentsRows.Close()

		var comments []map[string]string
		for commentsRows.Next() {
			var content, commentCreatedAt, commentUsername string
			if err := commentsRows.Scan(&content, &commentCreatedAt, &commentUsername); err != nil {
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			comments = append(comments, map[string]string{
				"content":    content,
				"created_at": commentCreatedAt,
				"username":   commentUsername,
			})
		}

		recipes = append(recipes, map[string]interface{}{
			"id":            id,
			"user_id":       userID,
			"title":         title,
			"ingredients":   ingredients,
			"instructions":  instructions,
			"photo":         photo,
			"created_at":    createdAt,
			"author":        author,
			"likes":         likes,
			"dislikes":      dislikes,
			"user_liked":    userLiked.Valid,
			"user_disliked": userDisliked.Valid,
			"Comments":      comments,
		})
	}

	err = tmpl.ExecuteTemplate(w, "recipes.html", map[string]interface{}{
		"Username":      username,
		"CurrentUserID": currentUserID,
		"Recipes":       recipes,
	})
	if err != nil {
		log.Printf("Ошибка отображения шаблона recipes: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	if session.Values["username"] == nil {
		log.Printf("Попытка доступа к профилю без авторизации")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user := session.Values["username"].(string)
	log.Printf("Пользователь %s просматривает свой профиль", user)

	rows, err := db.Query("SELECT recipes.id, recipes.title, recipes.ingredients, recipes.instructions, recipes.photo FROM recipes JOIN favorites ON recipes.id = favorites.recipe_id JOIN users ON users.id = favorites.user_id WHERE users.username = ?", user)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var favorites []map[string]string
	for rows.Next() {
		var id, title, ingredients, instructions, photo string
		if err := rows.Scan(&id, &title, &ingredients, &instructions, &photo); err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		favorites = append(favorites, map[string]string{
			"id":           id,
			"title":        title,
			"ingredients":  ingredients,
			"instructions": instructions,
			"photo":        photo,
		})
	}

	err = tmpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
		"Username":    user,
		"Favorites":   favorites,
		"CurrentPath": r.URL.Path,
	})
	if err != nil {
		log.Printf("Ошибка отображения шаблона profile: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Используем обертку для получения сессии
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	if session.Values["username"] != nil {
		log.Printf("Пользователь уже авторизован: %v", session.Values["username"])
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		log.Printf("Попытка входа пользователя: %s", username)

		var hashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
		if err != nil {
			log.Printf("Ошибка поиска пользователя: %v", err)
			http.Error(w, "Неверное имя пользователя или пароль", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			log.Printf("Неверный пароль для пользователя %s: %v", username, err)
			http.Error(w, "Неверное имя пользователя или пароль", http.StatusUnauthorized)
			return
		}

		// Очищаем сессию перед установкой нового значения
		session.Values = make(map[interface{}]interface{})
		session.Values["username"] = username

		err = session.Save(r, w)
		if err != nil {
			log.Printf("Ошибка сохранения сессии: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		log.Printf("Пользователь %s успешно авторизован", username)
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	err = tmpl.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		log.Printf("Ошибка отображения шаблона логина: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	if session.Values["username"] != nil {
		log.Printf("Авторизованный пользователь %v пытается зарегистрироваться", session.Values["username"])
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		log.Printf("Попытка регистрации пользователя: %s", username)

		if username == "" || password == "" {
			log.Printf("Отказано в регистрации: пустое имя пользователя или пароль")
			err = tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
				"Username": nil,
				"Error":    "Имя пользователя и пароль не могут быть пустыми",
			})
			if err != nil {
				log.Printf("Ошибка отображения шаблона register: %v", err)
				http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			}
			return
		}

		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
		if err != nil {
			log.Printf("Ошибка проверки существования пользователя: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		if exists {
			log.Printf("Пользователь %s уже существует", username)
			err = tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
				"Username": nil,
				"Error":    "Имя пользователя уже занято",
			})
			if err != nil {
				log.Printf("Ошибка отображения шаблона register: %v", err)
				http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			}
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Ошибка хеширования пароля: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
		if err != nil {
			log.Printf("Ошибка создания пользователя: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		log.Printf("Пользователь %s успешно зарегистрирован", username)

		// Очищаем сессию полностью перед авторизацией
		session.Values = make(map[interface{}]interface{})

		// Автоматически авторизуем пользователя после регистрации
		session.Values["username"] = username

		err = session.Save(r, w)
		if err != nil {
			log.Printf("Ошибка сохранения сессии после регистрации: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		// Переходим на профиль, теперь пользователь авторизован
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	err = tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
		"Username": nil,
		"Error":    nil,
	})
	if err != nil {
		log.Printf("Ошибка отображения шаблона register: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
	}
}

func addRecipeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, err := getSession(r)
	if err != nil {
		log.Printf("Критическая ошибка сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		// Получаем user_id
		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", session.Values["username"]).Scan(&userID)
		if err != nil {
			log.Printf("Ошибка получения user_id: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		title := r.FormValue("title")
		ingredients := r.FormValue("ingredients")
		instructions := r.FormValue("instructions")

		if title == "" || ingredients == "" || instructions == "" {
			http.Error(w, "Все поля кроме фото обязательны для заполнения", http.StatusBadRequest)
			return
		}

		var photoPath string
		file, handler, err := r.FormFile("photo")
		if err == nil {
			defer file.Close()

			// Создаем директорию images если её нет
			err = os.MkdirAll("images", os.ModePerm)
			if err != nil {
				log.Printf("Ошибка создания директории images: %v", err)
				http.Error(w, "Ошибка сервера при загрузке файла", http.StatusInternalServerError)
				return
			}

			// Генерируем уникальное имя файла
			ext := filepath.Ext(handler.Filename)
			fileName := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), title, ext)

			// Сохраняем файл локально
			localPath := filepath.Join("images", fileName)
			f, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				log.Printf("Ошибка сохранения файла: %v", err)
				http.Error(w, "Ошибка сохранения файла", http.StatusInternalServerError)
				return
			}
			defer f.Close()

			if _, err := io.Copy(f, file); err != nil {
				log.Printf("Ошибка копирования файла: %v", err)
				http.Error(w, "Ошибка при загрузке файла", http.StatusInternalServerError)
				return
			}

			// Сохраняем путь для базы данных
			photoPath = fmt.Sprintf("images/%s", fileName)
			log.Printf("Сохраняем фото с путем: %s", photoPath)
		}

		// Добавляем user_id в запрос
		result, err := db.Exec("INSERT INTO recipes (user_id, title, ingredients, instructions, photo) VALUES (?, ?, ?, ?, ?)",
			userID, title, ingredients, instructions, photoPath)
		if err != nil {
			log.Printf("Ошибка добавления рецепта в БД: %v", err)
			http.Error(w, "Ошибка сохранения рецепта", http.StatusInternalServerError)
			return
		}

		recipeID, _ := result.LastInsertId()
		log.Printf("Рецепт успешно добавлен с ID: %d и путем к фото: %s", recipeID, photoPath)

		http.Redirect(w, r, "/recipes", http.StatusSeeOther)
		return
	}

	// Для GET запроса отображаем форму
	err = tmpl.ExecuteTemplate(w, "add_recipe.html", map[string]interface{}{
		"Username": session.Values["username"],
	})
	if err != nil {
		log.Printf("Ошибка отображения шаблона: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func deleteRecipeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, _ := getSession(r)
	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	recipeID := r.FormValue("recipe_id")

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", session.Values["username"]).Scan(&userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Проверяем, является ли пользователь владельцем рецепта
	var recipeUserID int
	err = db.QueryRow("SELECT user_id FROM recipes WHERE id = ?", recipeID).Scan(&recipeUserID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if userID != recipeUserID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Удаляем все связанные комментарии
	_, err = db.Exec("DELETE FROM comments WHERE recipe_id = ?", recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Удаляем все связанные реакции
	_, err = db.Exec("DELETE FROM reactions WHERE recipe_id = ?", recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Удаляем все связанные избранные
	_, err = db.Exec("DELETE FROM favorites WHERE recipe_id = ?", recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Удаляем сам рецепт
	_, err = db.Exec("DELETE FROM recipes WHERE id = ?", recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/recipes", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Используем обертку для получения сессии
	session, _ := getSession(r)

	// Полностью очищаем сессию
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1 // Удаляем куки

	// Создаем также куки напрямую, чтобы гарантировать удаление
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)

	err := session.Save(r, w)
	if err != nil {
		log.Printf("Ошибка при удалении сессии: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func addFavoriteHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, _ := getSession(r)
	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := session.Values["username"].(string)

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	recipeID := r.FormValue("recipe_id")

	_, err = db.Exec("INSERT INTO favorites (user_id, recipe_id) VALUES (?, ?)", userID, recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/recipes", http.StatusSeeOther)
}

func removeFavoriteHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, _ := getSession(r)
	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := session.Values["username"].(string)

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	recipeID := r.FormValue("recipe_id")

	_, err = db.Exec("DELETE FROM favorites WHERE user_id = ? AND recipe_id = ?", userID, recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func favoritesHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, _ := getSession(r)
	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := session.Values["username"].(string)

	rows, err := db.Query("SELECT recipes.id, recipes.title, recipes.ingredients, recipes.instructions, recipes.photo FROM recipes JOIN favorites ON recipes.id = favorites.recipe_id JOIN users ON users.id = favorites.user_id WHERE users.username = ?", username)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var favorites []map[string]string
	for rows.Next() {
		var id, title, ingredients, instructions, photo string
		if err := rows.Scan(&id, &title, &ingredients, &instructions, &photo); err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		favorites = append(favorites, map[string]string{
			"id":           id,
			"title":        title,
			"ingredients":  ingredients,
			"instructions": instructions,
			"photo":        photo,
		})
	}

	tmpl.ExecuteTemplate(w, "favorites.html", map[string]interface{}{
		"Username":  username,
		"Favorites": favorites,
	})
}

func addCommentHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, _ := getSession(r)
	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	recipeID := r.FormValue("recipe_id")
	content := r.FormValue("content")

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", session.Values["username"]).Scan(&userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO comments (user_id, recipe_id, content) VALUES (?, ?, ?)",
		userID, recipeID, content)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/recipes", http.StatusSeeOther)
}

func addReactionHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	session, _ := getSession(r)
	if session.Values["username"] == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	recipeID := r.FormValue("recipe_id")
	reactionType := r.FormValue("type")

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", session.Values["username"]).Scan(&userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Удаляем предыдущую реакцию пользователя
	_, err = db.Exec("DELETE FROM reactions WHERE user_id = ? AND recipe_id = ?", userID, recipeID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Добавляем новую реакцию
	_, err = db.Exec("INSERT INTO reactions (user_id, recipe_id, type) VALUES (?, ?, ?)",
		userID, recipeID, reactionType)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/recipes", http.StatusSeeOther)
}

// Обработчик для отладки сессий
func debugSessionHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)

	// Выводим содержимое сессии
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>Отладка сессии</h1>")

	// Выводим информацию о куках
	fmt.Fprintf(w, "<h2>Cookies:</h2><ul>")
	for _, cookie := range r.Cookies() {
		fmt.Fprintf(w, "<li><strong>%s</strong>: %s</li>", cookie.Name, cookie.Value)
	}
	fmt.Fprintf(w, "</ul>")

	// Выводим информацию о сессии
	fmt.Fprintf(w, "<h2>Сессия:</h2>")
	if err != nil {
		fmt.Fprintf(w, "<p style='color:red'>Ошибка получения сессии: %v</p>", err)
	} else {
		fmt.Fprintf(w, "<p><strong>ID сессии:</strong> %s</p>", session.ID)
		fmt.Fprintf(w, "<p><strong>Новая сессия:</strong> %t</p>", session.IsNew)
		fmt.Fprintf(w, "<h3>Значения:</h3><ul>")
		for key, value := range session.Values {
			fmt.Fprintf(w, "<li><strong>%v</strong>: %v</li>", key, value)
		}
		fmt.Fprintf(w, "</ul>")
	}

	// Добавляем форму для установки значений сессии для отладки
	fmt.Fprintf(w, `
		<h2>Установить значение в сессию:</h2>
		<form method="post">
			<div>
				<label for="key">Ключ:</label>
				<input type="text" id="key" name="key" required>
			</div>
			<div>
				<label for="value">Значение:</label>
				<input type="text" id="value" name="value" required>
			</div>
			<button type="submit">Установить</button>
		</form>
	`)

	// Если POST запрос, устанавливаем значение в сессию
	if r.Method == http.MethodPost {
		key := r.FormValue("key")
		value := r.FormValue("value")

		session.Values[key] = value
		err = session.Save(r, w)
		if err != nil {
			fmt.Fprintf(w, "<p style='color:red'>Ошибка сохранения сессии: %v</p>", err)
		} else {
			fmt.Fprintf(w, "<p style='color:green'>Значение успешно установлено!</p>")
		}
	}
}
