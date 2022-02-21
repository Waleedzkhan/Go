# Go-MySQL-Example
Golang MySQL Signup Example

### Golang MySQL Signup Example 

#### Requires: 

* [golang.org/x/crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt)

* [github.com/go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)

### How To Run 

Create a new database with a users table 

```sql
CREATE TABLE users(
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(120)
);
```

Go get both required packages listed below 

```bash
go get golang.org/x/crypto/bcrypt

go get github.com/go-sql-driver/mysql
```

Inside of **signup.go** line **77** replace <example> with your own credentials

```go
db, err = sql.Open("mysql", "<root>:<password>@/<dbname>")
// Replace with 
db, err = sql.Open("mysql", "myUsername:myPassword@/myDatabase")

Sign in with google steps
1. Create an app on google cloud
2. Create OAuth credentials for the app
3. Enable GMail Api for the project
4. Download the credentials.json and place in the root of the project folder


Launching the application
1. Launch command prompt and change to the project root directory
2. type go run signup.go
3. Now go to the web browser and enter localhost:8080
```








