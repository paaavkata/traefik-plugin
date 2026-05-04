# Traefik plugin for API resources

## This Traefik plugin will have several functions:
- rate limit users on endpoints by session id passed by the front-end or identity jwt token if the user is signed in
- allow only admin level users to access the admin endpoints - manage internal resources, other users, conversions, jobs etc.
- decode jwt tokens and make sure the request is legit

## Some design decitions
- store limits and current usage in Redis
- integrate with a service called service-service. It contains data about every endpoint like level of access required, rate limits for different types of users and plans
- integrate with a service called usage-service. It will manage the usage of the user's credits and their limits


## The request can be stopped for several different reasons
- Unregistered users will have default rate limits applied for the free endpoints. 
- If the JWT token is expired or touched, request doesn't pass. 
- Check the user by their id from the JWT, If the user doesn't have admin status, and is requesting endpoints marked as admin, should be denied.