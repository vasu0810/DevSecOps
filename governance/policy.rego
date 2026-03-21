package devsecops

# Default values
default allow = false
default deny = {}

# Rule: Block if encryption is disabled
deny["Encryption disabled"] {
    input.encryption_disabled == 1
}

# Rule: Block if public exposure is requested in Production
deny["Public exposure in Prod"] {
    input.environment == "prod"
    input.public_exposure == 1
}

# Rule: Block if the AI Risk Engine score is above the safety threshold
deny["AI Risk score too high"] {
    input.risk_score > input.threshold
}

# Final Decision
allow {
    count(deny) == 0
}
package policy

default allow = false

# Rule: Allow only if NOT production
allow {
    input.environment != "prod"
}

# Rule: If Production, public exposure MUST be 0
allow {
    input.environment == "prod"
    input.public_exposure == 0
}