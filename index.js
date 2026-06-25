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
        req.user = payload
        next()
    } catch (error) {
        return res.status(401).json({ message: "Unauthorized" })
    }
    console.log(token)
}

const requireAdmin = (req, res, next) => {
    if (req.user?.role !== "admin") {
        return res.status(403).json({ message: "Forbidden: Admins only" })
    }
    next()
}

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect()

        const database = client.db("rentify")
        const allProperties = database.collection("properties")
        const allFavorites = database.collection("favorites")
        const allSubscriptions = database.collection("subscriptions")
        const allUsers = database.collection("user")
        const allBookings = database.collection("bookings")
        const allComments = database.collection("comments")

        // _______________________________________________________
        app.get("/api/properties/public", verifyToken, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1
                const limit = 9
                const skip = (page - 1) * limit

                // Build filter
                const filter = { status: "approved" }

                if (req.query.location) {
                    filter.location = { $regex: req.query.location, $options: "i" }
                }

                if (req.query.type && req.query.type !== "All") {
                    filter.propertyType = req.query.type
                }

                // Build sort
                let sortOption = { createdAt: -1 } // default: newest
                if (req.query.sort === "price_asc") sortOption = { price: 1 }
                if (req.query.sort === "price_desc") sortOption = { price: -1 }

                const total = await allProperties.countDocuments(filter)
                const properties = await allProperties.find(filter).sort(sortOption).skip(skip).limit(limit).toArray()

                res.json({
                    properties,
                    pagination: {
                        currentPage: page,
                        totalPages: Math.ceil(total / limit),
                        total
                    }
                })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Reject property with feedback
        app.patch("/api/properties/:id/reject", verifyToken, requireAdmin, async (req, res) => {
            try {
                const { id } = req.params
                const { feedback, rejectedBy } = req.body

                if (!feedback?.trim()) {
                    return res.status(400).json({ message: "Feedback is required" })
                }

                const result = await allProperties.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            status: "rejected",
                            feedback: feedback.trim(),
                            rejectedBy: rejectedBy || "admin",
                            rejectedAt: new Date(),
                            reviewedAt: new Date()
                        }
                    }
                )
                if (result.matchedCount === 0) return res.status(404).json({ message: "Property not found" })
                res.json({ success: true, message: "Property rejected" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Approve property
        app.patch("/api/properties/:id/approve", verifyToken, requireAdmin, async (req, res) => {
            try {
                const { id } = req.params
                const result = await allProperties.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: "approved", feedback: null, reviewedAt: new Date() } }
                )
                if (result.matchedCount === 0) return res.status(404).json({ message: "Property not found" })
                res.json({ success: true, message: "Property approved" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // get all properties
        app.get("/api/properties", verifyToken, requireAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1
                const limit = 10

                if (page < 1) return res.status(400).json({ error: "Page must be >= 1" })

                const skip = (page - 1) * limit
                const totalProperties = await allProperties.countDocuments()
                const properties = await allProperties.find().skip(skip).limit(limit).toArray()
                const totalPages = Math.ceil(totalProperties / limit)

                res.json({
                    properties,
                    pagination: {
                        currentPage: page,
                        totalPages,
                        totalProperties,
                        limit,
                        hasNextPage: page < totalPages,
                        hasPrevPage: page > 1
                    }
                })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // get all bookings
        app.get("/api/bookings", verifyToken, requireAdmin, async (req, res) => {
            try {
                const bookings = await allBookings.find().toArray()
                res.json(bookings)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // ______________________********User Management********______________
        // get all users
        app.get("/api/users", verifyToken, requireAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1 // Default page = 1
                const limit = 10 // Per page 10 users

                // Validation
                if (page < 1) {
                    return res.status(400).json({ error: "Page must be >= 1" })
                }

                // Calculate skip amount
                const skip = (page - 1) * limit

                // Get total count
                const totalUsers = await allUsers.countDocuments()

                // Get paginated users
                const users = await allUsers.find().skip(skip).limit(limit).toArray()

                // Calculate total pages
                const totalPages = Math.ceil(totalUsers / limit)

                // Response with metadata
                res.json({
                    users,
                    pagination: {
                        currentPage: page,
                        totalPages,
                        totalUsers,
                        limit,
                        hasNextPage: page < totalPages,
                        hasPrevPage: page > 1
                    }
                })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })
        // update user role to admin
        app.patch("/api/users/:id/role", verifyToken, requireAdmin, async (req, res) => {
            try {
                const { id } = req.params
                const { role } = req.body

                const result = await allUsers.updateOne({ _id: new ObjectId(id) }, { $set: { role } })

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "User not found" })
                }

                res.json({ message: "User role updated successfully" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // ______________________********Subscription********______________
        app.post("/api/bookings", verifyToken, async (req, res) => {
            try {
                const {
                    sessionId,
                    userId,
                    userEmail,
                    propertyId,
                    title,
                    nights,
                    totalPrice,
                    status,
                    bookedAt,
                    ownerEmail
                } = req.body

                const bookingsCollection = database.collection("bookings")

                const existing = await bookingsCollection.findOne({
                    userId,
                    propertyId,
                    status: "pending"
                })
                if (existing) {
                    return res.json({ message: "Already saved" })
                }

                const result = await bookingsCollection.insertOne({
                    sessionId,
                    userId,
                    userEmail,
                    propertyId,
                    title,
                    nights,
                    totalPrice,
                    status,
                    ownerEmail,
                    bookedAt: new Date(bookedAt),
                    createdAt: new Date()
                })

                res.json(result)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // get all bookings for a specific user by email
        app.get("/api/bookings/:email", verifyToken, async (req, res) => {
            try {
                const email = req.params.email
                const bookingsCollection = database.collection("bookings")

                const bookings = await bookingsCollection.find({ userEmail: email }).toArray()
                res.json(bookings)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // get all bookings for a specific owner by email
        app.get("/api/bookings/owner/:email", verifyToken, async (req, res) => {
            try {
                const email = req.params.email
                const bookingsCollection = database.collection("bookings")

                const bookings = await bookingsCollection.find({ ownerEmail: email }).toArray()
                res.json(bookings)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // update booking status to approved
        app.patch("/api/bookings/:id/approve", verifyToken, async (req, res) => {
            try {
                const { id } = req.params
                const { status } = req.body

                const bookingsCollection = database.collection("bookings")

                const result = await bookingsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: status } }
                )

                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: "Booking not found" })
                }

                res.json({ success: true, message: "Booking status updated" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // // admin planel thkek user pending ke approve korte hbe/ reject korte hbe
        // await allSubscriptions.updateOne(
        //     {_id: new ObjectId("64b8c9e5a1c2f0d9b8e4f1a") },
        //     { $set: { status: "approved" } }
        // )
        // // reject korte hbe
        // await allSubscriptions.updateOne(
        //     {_id: new ObjectId("64b8c9e5a1c2f0d9b8e4f1a") },
        //     { $set: { status: "rejected" } }
        // )

        app.post("/api/properties", verifyToken, async (req, res) => {
            try {
                const newProperty = {
                    ...req.body,
                    ownerEmail: req.user?.email || req.body.ownerEmail, // JWT থেকে নেওয়া, client-trusted না
                    createdAt: new Date()
                }
                const result = await allProperties.insertOne(newProperty)
                res.status(201).json({ success: true, insertedId: result.insertedId })
            } catch (err) {
                res.status(500).json({ success: false, message: err.message })
            }
        })

        // get all properties by owner email
        app.get("/api/properties/owner/:email", verifyToken, async (req, res) => {
            try {
                const { email } = req.params
                const properties = await allProperties.find({ ownerEmail: email }).toArray()
                res.json(properties)
            } catch (err) {
                res.status(500).json({ success: false, message: err.message })
            }
        })

        // patch property by id
        app.patch("/api/properties/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params
                const updateData = req.body

                const result = await allProperties.updateOne({ _id: new ObjectId(id) }, { $set: updateData })

                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: "Property not found" })
                }

                res.json({ success: true, message: "Property updated successfully" })
            } catch (err) {
                res.status(500).json({ success: false, message: err.message })
            }
        })

        // delete property by id
        app.delete("/api/properties/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params

                const result = await allProperties.deleteOne({ _id: new ObjectId(id) })

                if (result.deletedCount === 0) {
                    return res.status(404).json({ error: "Property not found" })
                }

                res.json({ success: true, message: "Property deleted successfully" })
            } catch (err) {
                res.status(500).json({ success: false, message: err.message })
            }
        })

        // app.get("/api/properties", verifyToken, async (req, res) => {
        //     const properties = await allProperties.find().toArray()
        //     res.json(properties)
        // })

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
