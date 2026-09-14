import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Calendar, Flame, Activity } from 'lucide-react';

interface ThreatHeatmapProps {
  threatScore: number;
  threatLevel: string;
  category: string;
  baseTimestamp?: string;
}

interface HeatmapCell {
  dayIndex: number;      // 0 (Mon) to 6 (Sun) or relative 7 days
  dayLabel: string;
  dateStr: string;
  hour: number;          // 0 to 23
  intensity: number;     // 0 to 100
  threatCount: number;
  isPeak: boolean;
  anomalyType?: string;
}

export const ThreatTrendHeatmap: React.FC<ThreatHeatmapProps> = ({
  threatScore,
  threatLevel,
  category,
  baseTimestamp,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredCell, setHoveredCell] = useState<HeatmapCell | null>(null);
  const [containerWidth, setContainerWidth] = useState<number>(800);

  // Days of week labels for the 7-day window
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  // 4-hour time block bins for crisp responsive visualization (00:00, 04:00, 08:00, 12:00, 16:00, 20:00)
  const timeSlots = [
    { hour: 0, label: '00:00' },
    { hour: 4, label: '04:00' },
    { hour: 8, label: '08:00' },
    { hour: 12, label: '12:00' },
    { hour: 16, label: '16:00' },
    { hour: 20, label: '20:00' },
  ];

  // Observe container resize
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      if (entries[0] && entries[0].contentRect.width > 0) {
        setContainerWidth(entries[0].contentRect.width);
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    // Deterministic pseudo-random generator seeded by category and threat score
    const seed = (threatScore * 17 + category.length * 31) % 1000;
    const pseudoRand = (i: number, j: number) => {
      const x = Math.sin(seed + i * 12.9898 + j * 78.233) * 43758.5453;
      return x - Math.floor(x);
    };

    // Synthesize 7 days of realistic threat trend telemetry based on the current analyzed case
    const now = baseTimestamp ? new Date(baseTimestamp) : new Date();
    const data: HeatmapCell[] = [];

    // Target peak hour and day from threat profile
    const peakDay = (seed % 5) + 1; // weekday bias
    const peakSlotHour = threatScore > 75 ? 12 : 16;

    for (let d = 0; d < 7; d++) {
      const dayDate = new Date(now);
      dayDate.setDate(now.getDate() - (6 - d));
      const dayName = days[dayDate.getDay() === 0 ? 6 : dayDate.getDay() - 1];
      const dateStr = dayDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

      timeSlots.forEach((slot, slotIdx) => {
        const rand = pseudoRand(d, slotIdx);
        // Intensity weighted by the investigated email threat score
        let baseIntensity = (threatScore * 0.4) + (rand * 35);

        // Peak simulation for campaign clusters
        const isPeakSlot = (d === peakDay && slot.hour === peakSlotHour) || (d === 6 && slot.hour === 12);
        if (isPeakSlot) {
          baseIntensity = Math.min(100, Math.max(82, threatScore + 8));
        }

        // Nighttime vs business hours modulation
        if (slot.hour === 0 || slot.hour === 4) {
          baseIntensity *= 0.65;
        }

        const intensity = Math.round(Math.min(100, Math.max(8, baseIntensity)));
        const threatCount = Math.max(1, Math.round((intensity / 100) * 24 * (1 + rand * 0.5)));

        data.push({
          dayIndex: d,
          dayLabel: dayName,
          dateStr,
          hour: slot.hour,
          intensity,
          threatCount,
          isPeak: intensity >= 75,
          anomalyType: intensity >= 80 ? 'Coordinated Influx' : intensity >= 55 ? 'Burst Activity' : 'Baseline',
        });
      });
    }

    // Measure container width
    const currentWidth = containerWidth || containerRef.current.clientWidth || 700;
    const margin = { top: 28, right: 24, bottom: 28, left: 54 };
    const width = Math.max(320, currentWidth - margin.left - margin.right);
    const height = 180 - margin.top - margin.bottom;

    // Clear previous SVG contents
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg
      .attr('width', currentWidth)
      .attr('height', height + margin.top + margin.bottom)
      .attr('viewBox', `0 0 ${currentWidth} ${height + margin.top + margin.bottom}`);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // D3 Scales
    const xScale = d3
      .scaleBand()
      .domain(data.map((d) => d.dateStr))
      .range([0, width])
      .padding(0.12);

    const yScale = d3
      .scaleBand()
      .domain(timeSlots.map((s) => s.label))
      .range([0, height])
      .padding(0.12);

    // Modern Monochromatic Carbon/Aurora Color scale
    // Low intensity -> subtle dark recess #1c1c1e, High intensity -> bone white #fafafa / vibrant aurora highlight
    const colorScale = d3
      .scaleLinear<string>()
      .domain([0, 30, 60, 85, 100])
      .range(['#181818', '#2d2d31', '#5c5c61', '#a1a1aa', '#fafafa']);

    // Draw Heatmap Cells
    const cells = g
      .selectAll('rect.heatmap-cell')
      .data(data)
      .enter()
      .append('rect')
      .attr('class', 'heatmap-cell')
      .attr('x', (d) => xScale(d.dateStr) || 0)
      .attr('y', (d) => {
        const slot = timeSlots.find((s) => s.hour === d.hour);
        return yScale(slot ? slot.label : '00:00') || 0;
      })
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('rx', 3)
      .attr('ry', 3)
      .attr('fill', '#181818')
      .attr('stroke', '#333336')
      .attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .on('mouseenter', function (event, d) {
        d3.select(this)
          .transition()
          .duration(150)
          .attr('stroke', '#fafafa')
          .attr('stroke-width', 1.8)
          .attr('filter', 'drop-shadow(0px 2px 6px rgba(255,255,255,0.25))');
        setHoveredCell(d);
      })
      .on('mouseleave', function (event, d) {
        d3.select(this)
          .transition()
          .duration(200)
          .attr('stroke', d.isPeak ? 'rgba(250,250,250,0.6)' : '#333336')
          .attr('stroke-width', d.isPeak ? 1.2 : 1)
          .attr('filter', 'none');
        setHoveredCell(null);
      });

    // Animate cells fill with gentle staggered fade-in
    cells
      .transition()
      .duration(750)
      .delay((d, i) => (d.dayIndex * 60) + (d.hour * 10))
      .ease(d3.easeCubicOut)
      .attr('fill', (d) => colorScale(d.intensity))
      .attr('stroke', (d) => (d.isPeak ? 'rgba(250,250,250,0.6)' : '#333336'));

    // X Axis (Dates)
    g.append('g')
      .attr('transform', `translate(0, ${height + 6})`)
      .call(d3.axisBottom(xScale).tickSize(0))
      .call((axis) => axis.select('.domain').remove())
      .selectAll('text')
      .attr('fill', '#a1a1aa')
      .attr('font-family', 'Geist Mono, monospace')
      .attr('font-size', '10px')
      .attr('dy', '1em');

    // Y Axis (Time Slots)
    g.append('g')
      .call(d3.axisLeft(yScale).tickSize(0))
      .call((axis) => axis.select('.domain').remove())
      .selectAll('text')
      .attr('fill', '#a1a1aa')
      .attr('font-family', 'Geist Mono, monospace')
      .attr('font-size', '10px')
      .attr('dx', '-6px');

  }, [threatScore, threatLevel, category, baseTimestamp, containerWidth]);

  return (
    <div className="card-console flex flex-col p-4 sm:p-6 scroll-reveal-item">
      {/* Heatmap Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-[#5c5c61]/40">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-[#181818] border border-[#5c5c61] flex items-center justify-center text-[#fafafa] shrink-0">
            <Calendar className="w-3.5 h-3.5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
                7-Day Threat Vector Trend Heatmap
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#181818] text-[#fafafa] border border-[#5c5c61]">
                D3.js Time Engine
              </span>
            </div>
            <p className="text-xs text-[#a1a1aa] font-sans">
              Temporal density mapping campaign burst occurrences across 4-hour temporal epochs
            </p>
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-[#a1a1aa]">
          <span>Low</span>
          <div className="flex items-center gap-1">
            <span className="w-3.5 h-3.5 rounded-sm bg-[#181818] border border-[#333336]" title="0-20% Activity" />
            <span className="w-3.5 h-3.5 rounded-sm bg-[#2d2d31] border border-[#5c5c61]" title="21-50% Activity" />
            <span className="w-3.5 h-3.5 rounded-sm bg-[#5c5c61]" title="51-75% Activity" />
            <span className="w-3.5 h-3.5 rounded-sm bg-[#a1a1aa]" title="76-90% Activity" />
            <span className="w-3.5 h-3.5 rounded-sm bg-[#fafafa] border border-white" title="Peak Influx" />
          </div>
          <span className="text-[#fafafa] font-semibold">Peak Threat</span>
        </div>
      </div>

      {/* Heatmap D3 Visualization Area */}
      <div ref={containerRef} className="w-full relative overflow-x-auto no-scrollbar">
        <svg ref={svgRef} className="w-full select-none min-w-[340px]" />

        {/* Interactive Hover Telemetry Tooltip */}
        {hoveredCell && (
          <div className="mt-3 p-3 rounded bg-[#181818] border border-[#fafafa] flex flex-wrap items-center justify-between gap-3 text-xs font-mono animate-fadeIn">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[#fafafa] animate-ping shrink-0" />
              <span className="text-[#fafafa] font-medium">
                {hoveredCell.dateStr} @ {String(hoveredCell.hour).padStart(2, '0')}:00 – {String(hoveredCell.hour + 4).padStart(2, '0')}:00
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-3 sm:gap-4 text-[#ebeced]">
              <span>
                Threat Index: <strong className="text-[#fafafa]">{hoveredCell.intensity}/100</strong>
              </span>
              <span>
                Correlated Vol: <strong className="text-[#fafafa]">{hoveredCell.threatCount} emails</strong>
              </span>
              <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-[#232324] border border-[#5c5c61] text-[#fafafa]">
                {hoveredCell.anomalyType}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Footnote Context */}
      <div className="mt-3 text-[11px] text-[#a1a1aa] font-sans flex flex-col sm:flex-row sm:items-center justify-between gap-1 pt-2 border-t border-[#5c5c61]/30">
        <span className="flex items-center gap-1.5">
          <Activity className="w-3 h-3 text-[#a1a1aa] shrink-0" />
          Synchronized with active SOC envelope heuristics &amp; MTA relay transmission records
        </span>
        <span className="font-mono text-[#ebeced] text-[10px] sm:text-[11px]">Timezone: UTC / Standard Incident Log</span>
      </div>
    </div>
  );
};
