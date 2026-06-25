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
        req.user = payload
        next()
    } catch (error) {
        return res.status(401).json({ message: "Unauthorized" })
    }
}

const requireAdmin = (req, res, next) => {
    if (req.user?.role !== "admin") {
        return res.status(403).json({ message: "Forbidden: Admins only" })
    }
    next()
}

const requireTenant = (req, res, next) => {
    if (req.user?.role !== "tenant") {
        return res.status(403).json({ message: "Forbidden: Tenants only" })
    }
    next()
}

const requireOwner = (req, res, next) => {
    if (req.user?.role !== "owner") {
        return res.status(403).json({ message: "Forbidden: Owners only" })
    }
    next()
}

const requireOwnerOrAdmin = (req, res, next) => {
    if (req.user?.role !== "owner" && req.user?.role !== "admin") {
        return res.status(403).json({ message: "Forbidden: Owners or Admins only" })
    }
    next()
}

async function run() {
    try {
        await client.connect()

        const database = client.db("rentify")
        const allProperties = database.collection("properties")
        const allFavorites = database.collection("favorites")
        const allSubscriptions = database.collection("subscriptions")
        const allUsers = database.collection("user")
        const allBookings = database.collection("bookings")
        const allReviews = database.collection("reviews")

        // ─────────────────────────────────────────
        // PROPERTIES — static routes first
        // ─────────────────────────────────────────

        // Latest approved properties (public)
        app.get("/api/properties/latest", async (req, res) => {
            try {
                const cursor = allProperties.find({ status: "approved" }).sort({ createdAt: -1 }).limit(6)
                const result = await cursor.toArray()
                res.json(result)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Public properties with filter/sort/pagination — NO verifyToken
        app.get("/api/properties/public", async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1
                const limit = 9
                const skip = (page - 1) * limit

                const filter = { status: "approved" }

                if (req.query.location) {
                    filter.location = { $regex: req.query.location, $options: "i" }
                }

                if (req.query.type && req.query.type !== "All") {
                    filter.propertyType = req.query.type
                }

                let sortOption = { createdAt: -1 }
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

        // Favorites — all favorited properties
        app.get("/api/properties/favorites/all", verifyToken, async (req, res) => {
            try {
                const favorites = await allProperties.find({ isFavorite: true }).toArray()
                res.json({
                    success: true,
                    count: favorites.length,
                    data: favorites
                })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Owner's own properties
        app.get("/api/properties/owner/:email", verifyToken, requireOwner, async (req, res) => {
            try {
                const { email } = req.params
                const properties = await allProperties.find({ ownerEmail: email }).toArray()
                res.json(properties)
            } catch (err) {
                res.status(500).json({ success: false, message: err.message })
            }
        })

        // All properties — admin only
        app.get("/api/properties", verifyToken, requireAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1
                const limit = 10

                if (page < 1) return res.status(400).json({ error: "Page must be >= 1" })

                const skip = (page - 1) * limit
                const totalProperties = await allProperties.countDocuments()
                const properties = await allProperties.find().skip(skip).limit(limit).sort({ createdAt: -1 }).toArray()
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

        // Add property — owner only
        app.post("/api/properties", verifyToken, requireOwner, async (req, res) => {
            try {
                const newProperty = {
                    ...req.body,
                    ownerEmail: req.user?.email || req.body.ownerEmail,
                    createdAt: new Date()
                }
                const result = await allProperties.insertOne(newProperty)
                res.status(201).json({ success: true, insertedId: result.insertedId })
            } catch (err) {
                res.status(500).json({ success: false, message: err.message })
            }
        })

        // Approve property — admin only
        app.patch("/api/properties/:id/approve", verifyToken, async (req, res) => {
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

        // Reject property — admin only
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

        // Toggle favorite
        app.patch("/api/properties/:id/favorite", verifyToken, async (req, res) => {
            try {
                const { id } = req.params
                const { isFavorite } = req.body

                const result = await allProperties.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { isFavorite: isFavorite } }
                )

                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: "Property not found" })
                }

                res.json({ success: true, message: "Property favorited successfully" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Update property — owner only
        app.patch("/api/properties/:id", verifyToken, requireOwnerOrAdmin, async (req, res) => {
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

        // Delete property — owner only
        app.delete("/api/properties/:id", verifyToken, requireOwnerOrAdmin, async (req, res) => {
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

        // Single property by id — ✅ dynamic route সবার শেষে
        app.get("/api/properties/:id", verifyToken, async (req, res) => {
            try {
                const id = req.params.id
                const result = await allProperties.findOne({ _id: new ObjectId(id) })
                if (!result) return res.status(404).json({ message: "Property not found" })
                res.json(result)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // ─────────────────────────────────────────
        // BOOKINGS
        // ─────────────────────────────────────────

        // All bookings — admin only
        app.get("/api/bookings", verifyToken, requireAdmin, async (req, res) => {
            try {
                const bookings = await allBookings.find().toArray()
                res.json(bookings)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Owner's bookings
        app.get("/api/bookings/owner/:email", verifyToken, requireOwner, async (req, res) => {
            try {
                const email = req.params.email
                const bookings = await allBookings.find({ ownerEmail: email }).toArray()
                res.json(bookings)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Tenant's bookings
        app.get("/api/bookings/:email", verifyToken, requireTenant, async (req, res) => {
            try {
                const email = req.params.email
                const bookings = await allBookings.find({ userEmail: email }).toArray()
                res.json(bookings)
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Create booking — tenant only
        app.post("/api/bookings", verifyToken, requireTenant, async (req, res) => {
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

                const existing = await allBookings.findOne({
                    userId,
                    propertyId,
                    status: "pending"
                })
                if (existing) {
                    return res.json({ message: "Already saved" })
                }

                const result = await allBookings.insertOne({
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

        // Update booking status — owner only
        app.patch("/api/bookings/:id/approve", verifyToken, requireOwner, async (req, res) => {
            try {
                const { id } = req.params
                const { status } = req.body

                const result = await allBookings.updateOne({ _id: new ObjectId(id) }, { $set: { status: status } })

                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: "Booking not found" })
                }

                res.json({ success: true, message: "Booking status updated" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // ─────────────────────────────────────────
        // USERS
        // ─────────────────────────────────────────

        // All users — admin only
        app.get("/api/users", verifyToken, requireAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1
                const limit = 10

                if (page < 1) {
                    return res.status(400).json({ error: "Page must be >= 1" })
                }

                const skip = (page - 1) * limit
                const totalUsers = await allUsers.countDocuments()
                const users = await allUsers.find().skip(skip).limit(limit).toArray()
                const totalPages = Math.ceil(totalUsers / limit)

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

        // Update user role — admin only
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

        // ─────────────────────────────────────────
        // REVIEWS
        // ─────────────────────────────────────────

        // Get reviews by propertyId (public)
        app.get("/api/reviews/:propertyId", async (req, res) => {
            try {
                const { propertyId } = req.params
                const reviews = await allReviews.find({ propertyId }).sort({ createdAt: -1 }).toArray()

                res.json({ success: true, reviews })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Add review
        app.post("/api/reviews", verifyToken, async (req, res) => {
            try {
                const { propertyId, rating, comment } = req.body
                const { email, name } = req.user

                if (!propertyId || !rating || !comment?.trim()) {
                    return res.status(400).json({ message: "propertyId, rating, comment required" })
                }

                const existing = await allReviews.findOne({ propertyId, userEmail: email })
                if (existing) {
                    return res.status(409).json({ message: "You have already reviewed this property" })
                }

                const review = {
                    propertyId,
                    userName: name,
                    userEmail: email,
                    rating: Number(rating),
                    comment: comment.trim(),
                    createdAt: new Date(),
                    updatedAt: new Date()
                }

                await allReviews.insertOne(review)

                // Recalculate averageRating
                const allPropertyReviews = await allReviews.find({ propertyId }).toArray()
                const totalReviews = allPropertyReviews.length
                const averageRating = allPropertyReviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews

                await allProperties.updateOne(
                    { _id: new ObjectId(propertyId) },
                    {
                        $set: {
                            "reviews.averageRating": parseFloat(averageRating.toFixed(1)),
                            "reviews.totalReviews": totalReviews
                        }
                    }
                )

                res.status(201).json({ success: true, message: "Review added" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // Edit review
        app.patch("/api/reviews/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params
                const { rating, comment } = req.body
                const { email } = req.user

                const review = await allReviews.findOne({ _id: new ObjectId(id) })

                if (!review) return res.status(404).json({ message: "Review not found" })
                if (review.userEmail !== email) return res.status(403).json({ message: "Forbidden" })

                await allReviews.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            rating: Number(rating),
                            comment: comment.trim(),
                            updatedAt: new Date()
                        }
                    }
                )

                // Recalculate averageRating
                const allPropertyReviews = await allReviews.find({ propertyId: review.propertyId }).toArray()
                const totalReviews = allPropertyReviews.length
                const averageRating = allPropertyReviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews

                await allProperties.updateOne(
                    { _id: new ObjectId(review.propertyId) },
                    {
                        $set: {
                            "reviews.averageRating": parseFloat(averageRating.toFixed(1)),
                            "reviews.totalReviews": totalReviews
                        }
                    }
                )

                res.json({ success: true, message: "Review updated" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        //  Delete review
        app.delete("/api/reviews/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params
                const { email } = req.user

                const review = await allReviews.findOne({ _id: new ObjectId(id) })

                if (!review) return res.status(404).json({ message: "Review not found" })
                if (review.userEmail !== email) return res.status(403).json({ message: "Forbidden" })

                await allReviews.deleteOne({ _id: new ObjectId(id) })

                // Recalculate averageRating
                const remaining = await allReviews.find({ propertyId: review.propertyId }).toArray()
                const totalReviews = remaining.length
                const averageRating =
                    totalReviews === 0 ? 0 : remaining.reduce((sum, r) => sum + r.rating, 0) / totalReviews

                await allProperties.updateOne(
                    { _id: new ObjectId(review.propertyId) },
                    {
                        $set: {
                            "reviews.averageRating": parseFloat(averageRating.toFixed(1)),
                            "reviews.totalReviews": totalReviews
                        }
                    }
                )

                res.json({ success: true, message: "Review deleted" })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        // ─────────────────────────────────────────
        // ANALYTICS
        // ─────────────────────────────────────────

        // Owner analytics
        app.get("/api/analytics/owner/:email", verifyToken, requireOwner, async (req, res) => {
            try {
                const { email } = req.params

                const totalProperties = await allProperties.countDocuments({ ownerEmail: email })

                const bookings = await allBookings.find({ ownerEmail: email, status: "approved" }).toArray()

                const totalBookings = bookings.length
                const totalEarnings = bookings.reduce((sum, b) => sum + (b.totalPrice || 0), 0)

                // Last 12 months
                const now = new Date()
                const monthlyMap = {}

                for (let i = 11; i >= 0; i--) {
                    const d = new Date(now.getFullYear(), now.getMonth() - i, 1)
                    const key = d.toLocaleString("en-US", { month: "short", year: "numeric" })
                    monthlyMap[key] = 0
                }

                bookings.forEach((b) => {
                    const d = new Date(b.bookedAt || b.createdAt)
                    const key = d.toLocaleString("en-US", { month: "short", year: "numeric" })
                    if (Object.prototype.hasOwnProperty.call(monthlyMap, key)) {
                        monthlyMap[key] += b.totalPrice || 0
                    }
                })

                const monthlyEarnings = Object.entries(monthlyMap).map(([name, value]) => ({
                    name: name.split(" ")[0],
                    value
                }))

                res.json({
                    totalEarnings,
                    totalProperties,
                    totalBookings,
                    monthlyEarnings
                })
            } catch (err) {
                res.status(500).json({ error: err.message })
            }
        })

        await client.db("admin").command({ ping: 1 })
        console.log("Pinged your deployment. You successfully connected to MongoDB!")
    } finally {
        // await client.close()
    }
}

run().catch(console.dir)

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
