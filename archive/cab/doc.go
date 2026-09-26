// Package cab reads Microsoft Cabinet files and cabinet sets through portable
// storage readers.
//
// Automatic detection follows a cabinet's declared previous and next names
// inside auto.Options.Source. The source tree must contain all volumes; opening
// any volume then exposes the complete set. Discovery validates set IDs,
// sequences, reciprocal links and bounded tree-relative paths before returning
// members. A missing source tree or companion is an error, even when an early
// cabinet contains some independently readable files. Callers with an explicit
// volume list can instead use OpenSetWithCache or archive.cab_set.
package cab
