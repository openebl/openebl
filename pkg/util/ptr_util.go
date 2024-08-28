package util

import (
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
)

func Ptr[V string | bool | bill_of_lading.PartyFunction | model.DateTime](s V) *V {
	return &s
}
