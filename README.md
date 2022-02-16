# AlgoRand Postgres extension by AlgoNode

## About pg_algorand

A set of utility functions to convert between binary arrays and various Algorand
textual object encodings.

## About AlgoNode

We operate a free algod and algorand-indexer valilla API service. 
Check us out at https://algonode.io

## Install 
```bash
sudo apt-get install postgresql-server-dev-X.Y  #Replace X.Y with your version of Postgres`
```

```bash
go install github.com/algonode/plgo/plgo@latest
git clone https://github.com/algonode/pg_algorand
cd pg_algorand
plgo
cd build
sudo make install with_llvm=no
```
```sql
CREATE EXTENSION pg_algorand;
```

## Usage

```sql
SELECT 
  COUNT(*) FROM account 
WHERE 
  addr = AddressTxt2Bin('ALGONODEIBJTET5OSEAXIHDSIEG7C2DOFB2WDYLRZTXN3NXVJ3NJD26L4E');
```    

```sql
SELECT 
  addr, AddressBin2Txt(addr) 
FROM 
  account 
LIMIT 1;
```

## Example views

```sql
CREATE OR REPLACE VIEW v_asset AS
SELECT
  index as asset_id
  ,creator_addr 
  ,AddressBin2Txt(creator_addr) creator
  ,deleted 
  ,created_at
  ,closed_at
  ,AddressBin2Txt(decode(params ->> 'c', 'base64')) clawback
  ,AddressBin2Txt(decode(params ->> 'f', 'base64')) freeze
  ,AddressBin2Txt(decode(params ->> 'm', 'base64')) manager
  ,AddressBin2Txt(decode(params ->> 'r', 'base64')) reserve
  ,CAST(params ->> 't' as NUMERIC(20,0)) total
  ,params ->> 'dc' as decimals
  ,params ->> 'am' as metadata
  ,params ->> 'au' as url
  ,params ->> 'an' as name
  ,params ->> 'un' as unit
  ,params ->> 'df' as frozen
FROM 
  asset
```



## Support AlgoNode

If you like what we do feel free to support us by sending some microAlgos to

**AlgoNode wallet**: `ALGONODEIBJTET5OSEAXIHDSIEG7C2DOFB2WDYLRZTXN3NXVJ3NJD26L4E`
