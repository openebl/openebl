package util

import "github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"

func Ptr[V string | bool | bill_of_lading.PartyFunction](s V) *V {
	return &s
}
