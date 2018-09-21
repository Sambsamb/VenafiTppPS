class TppObject {

    [string] $Name
    [string] $TypeName
    [string] $Path
    [string] $ParentPath
    [guid] $Guid

    [HashTable] ToHashtable() {

        $hash = @{}
        $propNames = $this | Get-Member | Where-Object {$_.MemberType -eq 'Property'} | Select-Object -ExpandProperty Name

        foreach ($prop in $propNames) {
            if ($this.GetType().GetProperty($prop)) {
                $hash.Add($prop, $this.$prop)
            }
        }

        return $hash
    }

    TppObject ([Hashtable] $InitHash) {

        if ( -not ($InitHash.Name -and $InitHash.Path -and $InitHash.TypeName -and $InitHash.Guid) ) {
            throw "Name, TypeName, Path, and Guid are required"
        }

        $this.Name = $InitHash.Name
        $this.TypeName = $InitHash.TypeName
        $this.Path = $InitHash.Path
        $this.Guid = $InitHash.Guid
    }

    TppObject (
        [string] $Name,
        [string] $TypeName,
        [string] $Path,
        [guid] $Guid
    ) {
        $this.Name = $Name
        $this.TypeName = $TypeName
        $this.Path = $Path
        $this.Guid = $Guid
        $this.ParentPath = $this.GetParentPath($Path)
    }

    TppObject ([string] $Path) {
        $info = ConvertTo-TppGuid -Path $Path -IncludeType
        $this.Path = $Path
        $this.Name = Split-Path $Path -Leaf
        $this.ParentPath = $this.GetParentPath($Path)
        $this.Guid = $info.Guid
        $this.TypeName = $info.TypeName
    }

    TppObject ([guid] $Guid) {
        $info = ConvertTo-TppPath -Guid $Guid -IncludeType
        $this.Guid = $Guid
        $this.Name = Split-Path $info.Path -Leaf
        $this.Path = $info.Path
        $this.ParentPath = $this.GetParentPath($info.Path)
        $this.TypeName = $info.TypeName
    }

    hidden [string] GetParentPath ([string] $Path) {
        $leafName = Split-Path $Path -Leaf
        # split-path -parent doesn't work on this path so use this workaround
        return $Path.Replace(("\{0}" -f $leafName), "")
    }

}
