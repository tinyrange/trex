package native

import (
	"context"
	"fmt"

	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/storage/star"
	windowsupdate "github.com/tinyrange/trex/windows/update"
	"go.starlark.net/starlark"
)

// Catalog and offers retain the original protocol metadata privately. Their
// exposed records are immutable; a caller cannot replace declared hashes or
// forge an offer from a different synchronization.
type catalogValue struct {
	*starvalue.Record
	catalog  *windowsupdate.Catalog
	options  windowsupdate.ScanOptions
	protocol windowsupdate.ClientProtocol
}

func (*catalogValue) Type() string { return "windows_update_catalog" }

type offerValue struct {
	*starvalue.Record
	catalog *catalogValue
	offer   windowsupdate.Offer
}

func (*offerValue) Type() string { return "windows_update_offer" }

// CatalogBuiltin synchronizes once with an explicit caller-authored profile.
// It exposes all revisions and declared file identities, without selecting an
// OS, rejecting previews, truncating the selection set or downloading payloads.
func CatalogBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	options, err := unpackScanOptions(args, kwargs)
	if err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, fmt.Errorf("update_catalog: %w", err)
	}
	protocol := windowsupdate.ClientProtocol{Transport: Transport{}}
	catalog, err := protocol.SyncCatalog(resources.Context(), options)
	if err != nil {
		return nil, fmt.Errorf("update_catalog: %w", err)
	}
	return newCatalogValue(catalog, options, protocol), nil
}

func unpackScanOptions(args starlark.Tuple, kwargs []starlark.Tuple) (windowsupdate.ScanOptions, error) {
	var device, caller *starlark.Dict
	var locales *starlark.List
	var options windowsupdate.ScanOptions
	if err := starlark.UnpackArgs("update_catalog", args, kwargs,
		"device_attributes", &device, "caller_attributes", &caller,
		"products", &options.Products, "locales", &locales,
		"user_agent", &options.UserAgent, "assume_non_leaf_installed", &options.AssumeNonLeafInstalled,
	); err != nil {
		return options, err
	}
	attributes := func(input *starlark.Dict) (map[string]string, error) {
		if input.Len() > 256 {
			return nil, fmt.Errorf("update_catalog: too many attributes")
		}
		result := make(map[string]string, input.Len())
		for _, item := range input.Items() {
			key, keyOK := starlark.AsString(item[0])
			value, valueOK := starlark.AsString(item[1])
			if !keyOK || !valueOK {
				return nil, fmt.Errorf("update_catalog: attributes must map strings to strings")
			}
			result[key] = value
		}
		return result, nil
	}
	var err error
	options.DeviceAttributes, err = attributes(device)
	if err != nil {
		return options, err
	}
	options.CallerAttributes, err = attributes(caller)
	if err != nil {
		return options, err
	}
	if locales.Len() > 64 {
		return options, fmt.Errorf("update_catalog: too many locales")
	}
	for index := 0; index < locales.Len(); index++ {
		value, ok := starlark.AsString(locales.Index(index))
		if !ok {
			return options, fmt.Errorf("update_catalog: locales must contain strings")
		}
		options.Locales = append(options.Locales, value)
	}
	return options, windowsupdate.ValidateScanOptions(options)
}

func newCatalogValue(catalog *windowsupdate.Catalog, options windowsupdate.ScanOptions, protocol windowsupdate.ClientProtocol) *catalogValue {
	value := &catalogValue{catalog: catalog, options: options, protocol: protocol}
	offers := make([]starlark.Value, 0, len(catalog.Revisions))
	leaves := 0
	for _, offer := range catalog.Revisions {
		files := make([]starlark.Value, 0, len(offer.Files))
		for _, file := range offer.Files {
			files = append(files, starvalue.NewRecord(starlark.StringDict{
				"name": starlark.String(file.Name), "size": starlark.MakeInt64(file.Size),
				"sha1": starlark.String(file.DigestSHA1), "sha256": starlark.String(file.DigestSHA256),
			}))
		}
		record := starvalue.NewRecord(starlark.StringDict{
			"id": starlark.String(offer.ID), "revision": starlark.MakeInt(offer.Revision),
			"server_id": starlark.String(offer.ServerID), "is_leaf": starlark.Bool(offer.IsLeaf),
			"title": starlark.String(offer.Title), "product_release": starlark.String(offer.ProductRelease),
			"deployment": starlark.String(offer.Deployment), "update_type": starlark.String(offer.UpdateType),
			"files": starlark.NewList(files), "file_count": starlark.MakeInt(len(files)),
			"prerequisites":   relationshipRecords(offer.Prerequisites),
			"bundled_updates": relationshipRecords(offer.BundledUpdates),
		})
		record.Freeze()
		offers = append(offers, &offerValue{Record: record, catalog: value, offer: offer})
		if offer.IsLeaf {
			leaves++
		}
	}
	value.Record = starvalue.NewRecord(starlark.StringDict{
		"offers": starlark.NewList(offers), "rounds": starlark.MakeInt(catalog.Rounds),
		"revision_count": starlark.MakeInt(len(offers)), "leaf_count": starlark.MakeInt(leaves),
	})
	value.Record.Freeze()
	return value
}

func relationshipRecords(clauses []windowsupdate.RelationshipClause) starlark.Value {
	result := make([]starlark.Value, 0, len(clauses))
	for _, clause := range clauses {
		alternatives := make([]starlark.Value, 0, len(clause.Alternatives))
		for _, identity := range clause.Alternatives {
			alternatives = append(alternatives, starvalue.NewRecord(starlark.StringDict{
				"id": starlark.String(identity.ID), "revision": starlark.MakeInt(identity.Revision),
			}))
		}
		result = append(result, starvalue.NewRecord(starlark.StringDict{
			"alternatives": starlark.NewList(alternatives), "is_category": starlark.Bool(clause.IsCategory),
		}))
	}
	return starlark.NewList(result)
}

func selectedOffer(catalogArg, offerArg starlark.Value) (*catalogValue, windowsupdate.Offer, error) {
	catalog, ok := catalogArg.(*catalogValue)
	if !ok {
		return nil, windowsupdate.Offer{}, fmt.Errorf("update_media: catalog must come from update_catalog")
	}
	offer, ok := offerArg.(*offerValue)
	if !ok || offer.catalog != catalog {
		return nil, windowsupdate.Offer{}, fmt.Errorf("update_media: offer must belong to the supplied catalog")
	}
	if offer.offer.ID == "" || offer.offer.Revision <= 0 {
		return nil, windowsupdate.Offer{}, fmt.Errorf("update_media: selected offer has no concrete update identity")
	}
	return catalog, offer.offer, nil
}

// Resolving payload locations reuses the original catalog/profile. It cannot
// silently rescan, rank other offers, or switch the caller's selected revision.
func (catalog *catalogValue) resolveFiles(ctx context.Context, offer windowsupdate.Offer) ([]windowsupdate.Offer, []windowsupdate.File, error) {
	closure, err := catalog.catalog.ResolveBundleClosure(offer)
	if err != nil {
		return nil, nil, err
	}
	files, err := catalog.protocol.ResolveFilesForOffers(ctx, catalog.options, closure)
	return closure, files, err
}
