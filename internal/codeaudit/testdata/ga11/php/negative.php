<?php
// Benign PHP: none of the thirteen families may fire on this file.
declare(strict_types=1);

namespace Acme\Reports;

final class MovingAverage
{
    /** @var list<float> */
    private array $values = [];

    public function __construct(array $values)
    {
        $this->values = array_values($values);
    }

    public function mean(): float
    {
        $count = count($this->values);
        if ($count === 0) {
            return 0.0;
        }
        return array_sum($this->values) / $count;
    }
}

function render_report(array $values, string $title): string
{
    $mean = (new MovingAverage($values))->mean();
    $rows = array_map(static fn (float $v): string => number_format($v, 3), $values);
    $path = __DIR__ . "/templates/report.tpl";
    $template = file_get_contents($path);
    $body = sprintf($template, $title, $mean, implode(", ", $rows));
    if (getenv("APP_MODE") === "debug") {
        error_log("report rendered");
    }
    echo $body;
    return $body;
}
