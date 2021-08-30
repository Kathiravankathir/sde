//jshint esversion:6

// ==================in built modules=============================

const express = require("express");
const bodyParser = require("body-parser");
const passport = require("passport");
const bcrypt = require('bcrypt');
const session=require('express-session');
const LocalStrategy = require("passport-local").Strategy;

const { Client }  = require("pg");

// ====================initial declarations========================

const connectionString = `postgresql://kbzhrdb1:kbzhrdb1@kbzhrdbdev.c9x2ofbqrrou.us-east-1.rds.amazonaws.com:5432/kathiravan`;
const app = express();


// ====================postgres connection=======================

const client = new Client({
    connectionString,
});

client.connect();

//=============Pass config=======================

passport.use(new LocalStrategy( async function(username, password, done) {
    try {
        const user = await client.query(`select * from users where username = '${username}'`);
        const validatePassword = await bcrypt.compare(password, user.rows[0].password);

        if(user.rows.length === 0) {
            console.log("incorrect username", user.rows.length);
            return done(null, false, { message: "Incorrect username." });
        }
        if(!validatePassword) {
            console.log("incorrect password", user.rows[0].password);
            return done(null, false, { message: "Incorrect password." });
        }
        console.log(user.rows[0]);
        return done(null, user.rows[0]);
    } catch(err) {
        console.log(err);
        return done(err);
    }
}));

passport.serializeUser(function(user, done) {
    done(null, user.uid);
});
  
passport.deserializeUser( async function(id, done) {
    try {
        const user = await client.query(`select * from users where uid = ${id}`);
        done(null, user.rows[0]);
    } catch(err) {
        console.log(err);
    }
});

//======================app uses====================================

app.use(bodyParser.urlencoded({extended: true}));
app.use(session({ 
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

//========================Route handlers============================

const checkAuthenticated = (req, res, next) => {
    if(req.isAuthenticated()) {
        return next();
    } else {
        res.status(403).send({message: "Access is forbidden. Login first"});
    }
}

//========================signup routes=============================


/* async function isUserExists(username) {
    return new Promise(resolve => {
        client.query(`SELECT * FROM users WHERE username = $1`, [username], (error, results) => {
            if (error) {
                throw error;
            }

            return resolve(results.rowCount > 0);
        });
    });
}

async function getUser(username) {
    return new Promise(resolve => {
        client.query(`SELECT * FROM users WHERE username = $1`, [username], (error, results) => {
            if (error) {
                throw error;
            }

            return resolve(results.rows[0]);
        });
    });
}

const createUser = (request, response) => {
    const saltRounds = 10;
    const { username,  password } = request.body;

    if (!username || username.length === 0) {
        return response.status(400).json({ status: 'failed', message: 'Name is required.' });
    }


    if (!password || password.length === 0) {
        return response.status(400).json({ status: 'failed', message: 'Password is required' });
    }

    isUserExists(username).then(isExists => {
        if (isExists) {
            return response.status(400).json({ status: 'failed', message: 'Email is taken.' });
        }

        bcrypt.hash(password, saltRounds, (error, encryptedPassword) => {
            if (error) {
                throw error;
            }

            client.query(`INSERT INTO users (username, password) VALUES ($1, $2)`, [username, encryptedPassword], error => {
                if (error) {
                    return response.status(400).json({ status: 'failed', message: error.code });
                }

                getUser(username).then(user => {
                    user = {
                        username: user.username,
                        message: "Successfully registered"
                    };

                    response.status(201).json(user);
                });
                
            });
        });
    }, error => {
        response.status(400).json({ status: 'failed', message: 'Error while checking is user exists.' });
    });
};
app.route('/signup').post(createUser); */

app.post("/signup", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    try {
        const user = await client.query(`insert into users(username, password) values($1, $2) returning *`, [username, hashedPassword]);
    
        res.send({message: "successfully created"});
    } catch (err) {
        console.log(err);
        res.status(401).send("Authorization information is missing or invalid");
    }
});

    
// ===========================login routes==========================

/* const login = (request, response) => {
    const { username, password } = request.body;

    isUserExists(username).then(isExists => {
        if (!isExists) {
            return response.status(401).json({ status: 'failed', message: 'Not registered' });
        }

        getUser(username).then(user => {
            bcrypt.compare(password, user.password, (error, isValid) => {
                if (error) {
                    throw error;
                }

                if (!isValid) {
                    return response.status(401).json({ status: 'failed', message: 'Invalid email or password!' });
                }

                response.status(200).json({ status: 'success', message: 'Login successfully!' });
            });
        });
    }, error => {
        response.status(400).json({ status: 'failed', message: 'Error while login.' });
    });
};

app.route('/login').post(login); */
app.post("/login", passport.authenticate("local"), (req, res) => {
    res.status(200).send({message: "login successful", username: req.body.username});
});

// ===========================book meeting routes====================

app.post("/bookMeeting", checkAuthenticated, async (req, res) => {
    const meeting = [
        
        req.body.title,
        req.body.date_of_meet,
        req.body.start_time,
        req.body.end_time,
        req.body.description || null,
        req.body.username
    ];

    const attendees = (req.body.attendees).split(",").map(attendee => attendee.trim());
    attendees.push(req.body.username);
    
    try {
        attendees.forEach( async (attendee) => {
            const clashTime = await client.query(`select m.*, u.username
            from users u
            inner join attendees a
            on u.username = a.username
            inner join meeting m
            on m.meeting_id = a.meeting_id
            where u.uid = (select uid from users where username = '${attendee}') and m.date_of_meet = '${meeting[1]}' and not('${meeting[2]}' >= m.end_time or '${meeting[3]}' <= m.start_time)`);

            if(clashTime.rows.length !== 0) {
                res.status(400).send({"message" : "Meeting not created. Another meeting is overlapping during this time slot"});
            }
        });
        
        const user = await client.query(`insert into meeting (title, date_of_meet, start_time, end_time, description, username) values('${meeting[0]}', '${meeting[1]}','${meeting[2]}','${meeting[3]}','${meeting[4]}','${meeting[5]}') returning *`);
        console.log(user);

        attendees.forEach(async (attendee) => {
            const validAttendee = await client.query(`insert into attendees values(${user.rows[0].meeting_id}, (select username from users where username='${attendee}'))`);
            console.log(validAttendee);
        });

        res.status(200).send({message: "Confirmed", ...req.body });
    } 
    catch(err) {
        res.status(500).send("Some error occurred on the server")
        console.log(err);
    }
});

// ===========================view meeting routes======================

app.get("/viewMeeting", checkAuthenticated, async (req, res) => {
    const username = req.body.username;
    const startDate = req.body.start_date;
    const endDate = req.body.end_date;
    
    try {
        const meetingList = await client.query(`select u.uid, u.username, m.title, m.date_of_meet, m.start_time, m.end_time
        from users u inner join attendees a
        on u.username = a.username
        inner join meeting m
        on m.meeting_id = a.meeting_id
        where u.uid = (select uid from users where username = '${username}') and m.date_of_meet between '${startDate}' and '${endDate}'
        order by m.date_of_meet, m.start_time`);

        res.status(200).send(meetingList.rows);
    } catch(err) {
        console.log(err);
    }
});

// ===============================report routes===========================

app.get("/report", checkAuthenticated,async (req, res) => {
    const topXEmployees = req.body.topXEmployees;
    const startDate = req.body.start_date;
    const endDate = req.body.end_date;

    try {
        const topXEmployeesList = await client.query(`select u.username, sum(extract (epoch from (m.end_time - m.start_time))::integer/60) as duration
        from users u inner join attendees a
        on u.username = a.username
        inner join meeting m
        on m.meeting_id = a.meeting_id
        where m.date_of_meet between '${startDate}' and '${endDate}'
        group by username
        order by duration desc limit ${topXEmployees}`);

        res.status(200).send(topXEmployeesList.rows);
    } catch(err) {
        console.log(err);
    }
});


//========================logout=====================================

app.get("/logout", (req, res) => {
    req.logout();
    res.status(200).send({message: "logout successful", user: req.user});
});

// =============================app listen================================

const PORT=8888;
app.listen(PORT, () => {
    console.log("server started");
});

// =============================error codes===============================

// 200 The API request was accepted and the response was returned successfully. The response will be of application/json content-type.

// 400 A Bad Request was sent. One of the parameters passed isn’t valid.

// 401 Authorization information is missing or invalid.

// 403 Access is forbidden

// 404 The requested API isn’t available.

// 500 Some error occurred on the server.