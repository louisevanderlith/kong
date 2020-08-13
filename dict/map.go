package dict

type Map []KeyValue

func (m Map) Get(key string) string {
	for _, v := range m {
		if v.Key == key {
			return v.Value
		}
	}

	return ""
}
