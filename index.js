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
        const allFavorites = database.collection("favorites")

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

        app.get("/api/properties/:id", verifyToken, async (req, res) => {
            const id = req.params.id

            const result = await allProperties.findOne({ _id: new ObjectId(id) })
            res.json(result)
        })

        // ______________________********Favorite********______________

        app.patch("/api/properties/:id/favorite", verifyToken, async (req, res) => {
            try {
                const { id } = req.params
                const { isFavorite } = req.body

                // Update the property document
                const result = await allProperties.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { isFavorite: isFavorite } }
                )

                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: "Property not found" })
                }

                res.json({
                    success: true,
                    message: "Property favorited successfully",
                    result: result
                })
            } catch (error) {
                console.error("Error updating favorite:", error)
                res.status(500).json({ error: "Failed to update favorite" })
            }
        })

        app.get("/api/properties/favorites/all", verifyToken, async (req, res) => {
            try {
                // Find all properties where isFavorite is true
                const favorites = await allProperties.find({ isFavorite: true }).toArray()

                res.json({
                    success: true,
                    count: favorites.length,
                    data: favorites
                })
            } catch (error) {
                console.error("Error fetching favorites:", error)
                res.status(500).json({ error: "Failed to fetch favorites" })
            }
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
