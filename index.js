const express = require("express")
const cors = require("cors")

const { createRemoteJWKSet, jwtVerify } = require("jose-cjs")

const app = express()
require("dotenv").config()
const port = 5000

app.use(cors())
app.use(express.json())

app.get("/", (req, res) => {
    res.send("Hello World!")
})

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb")
const uri = process.env.MONGODB_URI

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true
    }
})

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`))

const verifyToken = async (req, res, next) => {
    const authHeader = req?.headers.authorization

    if (!authHeader) {
        return res.status(401).json({ message: "Unauthorized" })
    }

    const token = authHeader?.split(" ")[1]

    if (!token) {
        return res.status(401).json({ message: "Unauthorized" })
    }

    try {
        const { payload } = await jwtVerify(token, JWKS)
        console.log("Verified Payload:", payload)
        next()
    } catch (error) {
        return res.status(401).json({ message: "Unauthorized" })
    }
    console.log(token)
}

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect()

        const database = client.db("rentify")
        const allProperties = database.collection("properties")

        app.post("/api/properties", async (req, res) => {
            const newProperty = req.body
            const result = await allProperties.insertOne(newProperty)
            res.json(result)
        })

        app.get("/api/properties", verifyToken, async (req, res) => {
            const properties = await allProperties.find().toArray()
            res.json(properties)
        })

        app.get("/api/properties/latest", async (req, res) => {
            const cursor = allProperties.find().sort({ createdAt: -1 }).limit(6)
            const result = await cursor.toArray()
            res.send(result)
        })

        app.get("/api/properties/:id", async (req, res) => {
            const id = req.params.id

            const result = await allProperties.findOne({ _id: new ObjectId(id) })
            res.json(result)
        })

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 })
        console.log("Pinged your deployment. You successfully connected to MongoDB!")
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close()
    }
}

run().catch(console.dir)

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
