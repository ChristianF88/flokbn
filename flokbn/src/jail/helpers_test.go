package jail

// Len returns the number of records.
func (j *Jail) Len() int { return len(j.records) }

// Records returns the records in address order, a range before everything
// inside it. The slice is the jail's own: read it, do not keep or change it.
func (j *Jail) Records() []Record { return j.records }
