import express from 'express';
import mysql2 from 'mysql2';
import cors from 'cors';
import jwt  from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieparser from'cookie-parser'
const salt = 10;
const app = express();
app.use( express.json() );  
app.use(
  cors({
      origin: [ "http://localhost:3000" ],
      methods: [ 'POST', 'GET' ],
      credentials: true
  })
);  
app.use( cookieparser() )

const db = mysql2.createConnection({
  host: "localhost",
  user: "root",
  password: "Ayfo@19!",
  database: "signup"  
});

// db.query("CREATE DATABASE signup", function (err, result) {
//   if (err) throw err;
//   console.log("Database created");
// });


   let sql = `CREATE TABLE if not exists login(
    user_id int auto_increment,
    user_name varchar(255) not null,
    user_email varchar(255) not null,
    user__password varchar(255) not null,
    PRIMARY KEY (user_id))`;
   db.query(sql, function (err, result) {
     if (err) throw err;
     console.log("Table created");
   } );
   
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    console.log( req );
    if ( !token )
    {
        return res.json({Error: "you are not Authenticated"})
    }
    else
    {
        jwt.verify( token, "jwt-secret-key", ( err, decoded ) =>
        {
            console.log( decoded );
            if ( err )
            {
                return res.json({Error: "token is not okay"})
            }
            else
            {
                req.name = decoded.name;
                next();  
            }
        });
    }
};

app.get( "/", verifyUser, ( req, res ) =>
{
    return res.json( { Status: "Success", name: req.name } );
});


app.post( '/register', ( req, res ) =>
{
    var sql = "INSERT INTO login (user_name, user_email, user__password) VALUES (?)";
    
    bcrypt.hash( req.body.password.toString(), salt, ( err, hash ) =>
    {
        if ( err ) return res.json( { Error: " Error during hashing" } )
        
        const values = [ req.body.name, req.body.email, hash ]
        db.query( sql, [values], function ( err, result )
        {
            if ( err )
            {   console.log("Insertion Error")
                return res.json( { Error: "Inserting data Error" } );
            }
            else
            {
                console.log(`Insert Successfully  ${result}`)
                return res.json( { Status: "Success" } )
            }
        })
    })
})


app.post( '/login', ( req, res ) =>
{
    const sql = `SELECT *  FROM login WHERE user_email = ?`;
    // we dont select the password the password is hash
    db.query( sql, [ req.body.email ], ( err, data ) =>
    {
        if ( err ) return res.json( { Error: " Data base Connection error" } )
        if ( data.length > 0 )
        {
            bcrypt.compare( req.body.password.toString(), data[ 0 ].user__password, (( err, response) =>
            {
                if ( err ) return res.json( { Error: 'password compare Error' } )
                if ( response )
                {
                    console.log( data )
                    const name = data[ 0 ].user_name;
                    const token = jwt.sign( { name }, "jwt-secret-key", {expiresIn: '1d'});
                   // let us stor the the token inside cookies
                    res.cookie( 'token', token );
                    return res.json( { Status: "Success" } );
                }   
                else   
                {
                    return res.json({Error: "password Not match"})
                }
            }) )
        }   
        else
        {
            return res.json({Error: 'No Email Exists'})
        }
    })
} )

app.get( "/logout", ( req, res ) =>
{
    console.log("mn alke")
    res.clearCookie( "token" );
    return res.json( { Status: "Success" } );
})

app.listen( 8081, ( err ) =>
{
    if ( err ) console.log( err )
    console.log("i am listening Ayfo")
} )     

