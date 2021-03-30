# mbclib
A library for querying the STIX data for the MBC (Malware Behavior Catalog).

## Progress
Currently being developed along with the [mbscan.py tool](https://github.com/accidentalrebel/mbcscan).

## About the Malware Behavior Catalog
The Malware Behavior Catalog (MBC) is a catalog of malware objectives and behaviors, created to support malware analysis-oriented use cases, such as labeling, similarity analysis, and standardized reporting. More info [here](https://github.com/MBCProject/mbc-markdown/blob/master/yfaq/README.md).

## Available functions

| Fetch Functions              | Description                                                                            |
|------------------------------|----------------------------------------------------------------------------------------|
| get_all_objectives           | Fetches all objectives                                                                 |
| get_all_behaviors            | Fetches all behaviors                                                                  |
| get_all_malwares             | Fetches all malware                                                                    |
| get_objective_by_id          | Get an objective by id (x-mitre-tactic--0735bfd3-bffa-4476-9e3b-e33cc5c553e0)          |
| get_objective_by_external_id | Get an objective by external id (x-mitre-tactic--0735bfd3-bffa-4476-9e3b-e33cc5c553e0) |
| get_objective_by_shortname   | Get an objective by shortname (file-system-micro-objective)                            |
| get_behavior_by_id           | Get a behavior by id (attack-pattern--001ca78e-188e-4725-9f43-706d0f487837)            |
| get_behavior_by_external_id  | Get a behavior by external id (B0030.001)                                              |
| get_malware_by_id            | Get a malware by id (malware--0c0d59b7-4ff0-4a09-9c64-558334485ece)                    |
| get_malware_by_external_id   | Get a malware by external id (X0005)                                                   |

| Property functions  | Description                                          |
|---------------------|------------------------------------------------------|
| get_mbc_external_id | Given an mbc object, return the mbc external id      |
| get_parent_behavior | Get the related parent behavior for a given behavior |

| Relationship functions        | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| get_relationships_by          | Get a list of related mbc objects, returned mbc object depends on the input |
| get_behaviors_used_by_malware | Get a list of behaviors used by a given malware                                   |
| get_malwares_using_behavior   | Get a list of malware that uses a given behavior                            |

