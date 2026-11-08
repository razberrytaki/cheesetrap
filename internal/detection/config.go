package detection

// Config is the nonsecret, validated threshold subset. Window duration,
// suspicious paths and exploit signatures remain code-versioned policy.
type Config struct {
	SSHRepeatThreshold       int `json:"ssh_repeat_threshold" minimum:"2" maximum:"10000"`
	WebRepeatThreshold       int `json:"web_repeat_threshold" minimum:"2" maximum:"10000"`
	WebDistinctPathThreshold int `json:"web_distinct_path_threshold" minimum:"1" maximum:"5"`
}

func DefaultConfig() Config {
	return Config{SSHRepeatThreshold: 10, WebRepeatThreshold: 20, WebDistinctPathThreshold: 5}
}
func (c Config) Valid() bool {
	return c.SSHRepeatThreshold >= 2 && c.SSHRepeatThreshold <= 10000 && c.WebRepeatThreshold >= 2 && c.WebRepeatThreshold <= 10000 && c.WebDistinctPathThreshold >= 1 && c.WebDistinctPathThreshold <= 5 && c.WebRepeatThreshold >= c.WebDistinctPathThreshold
}
