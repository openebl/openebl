package bill_of_lading

type Location struct {
	LocationName             string                   `json:"locationName"`
	Address                  *Address                 `json:"address"`
	UNLocationCode           string                   `json:"UNLocationCode"` // UN Location Code. Example: USLAX
	FacilityCode             string                   `json:"facilityCode"`   // Facility Code. The code does not include the UN Location Code.
	FacilityCodeListProvider FacilityCodeListProvider `json:"facilityCodeListProvider"`
}
